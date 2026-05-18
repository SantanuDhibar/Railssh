// server.ts
import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

const UUID = Deno.env.get("UUID") || Deno.env.get("VLESS_UUID") || "f9a1ba12-7187-4b25-a5d5-7bafd82ffb4d";
const DOMAIN = Deno.env.get("DOMAIN") || Deno.env.get("RAILWAY_PUBLIC_DOMAIN") || "localhost";
const WS_PATH = Deno.env.get("WS_PATH") || "ws";
const SUB_PATH = Deno.env.get("SUB_PATH") || "sub";
const SSH_PATH = Deno.env.get("SSH_PATH") || "ssh";
const PORT = parseInt(Deno.env.get("PORT") || "3000");

// Allowed SSH targets (security)
const ALLOWED_SSH_HOSTS = Deno.env.get("ALLOWED_SSH_HOSTS")?.split(",") || [];
const MAX_PAYLOAD_SIZE = 1024 * 1024; // 1MB
const BUFFER_SIZE = 32768;

console.log("Starting SSH/VLESS WebSocket Tunnel Server...");
console.log(`Configuration:`);
console.log(`  - Port: ${PORT}`);
console.log(`  - Domain: ${DOMAIN}`);
console.log(`  - VLESS Path: /${WS_PATH}`);
console.log(`  - SSH Path: /${SSH_PATH}`);
console.log(`  - Subscription Path: /${SUB_PATH}`);
console.log(`  - Allowed SSH Hosts: ${ALLOWED_SSH_HOSTS.length ? ALLOWED_SSH_HOSTS.join(", ") : "any"}`);

// ---------------- UUID utilities ----------------

function parseUUID(uuid: string): Uint8Array {
  uuid = uuid.replace(/-/g, "");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = parseInt(uuid.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function uuidEqual(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < 16; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ---------------- VLESS header parser ----------------

async function parseVLESSHeader(data: Uint8Array) {
  if (data.length < 20) {
    throw new Error("Invalid VLESS header: too short");
  }

  const version = data[0];
  const id = data.slice(1, 17);

  if (!uuidEqual(id, parseUUID(UUID))) {
    throw new Error("Invalid UUID");
  }

  const optLen = data[17];
  if (data.length < 19 + optLen) {
    throw new Error("Invalid VLESS header: options length mismatch");
  }

  const cmd = data[18 + optLen];
  if (cmd !== 1) throw new Error("Only TCP supported");

  const portIndex = 19 + optLen;
  if (data.length < portIndex + 4) {
    throw new Error("Invalid VLESS header: address/port missing");
  }

  const port = (data[portIndex] << 8) + data[portIndex + 1];
  const addrType = data[portIndex + 2];

  let host = "";
  let addrIndex = portIndex + 3;

  if (addrType === 1) {
    // IPv4
    if (data.length < addrIndex + 4) throw new Error("Invalid IPv4 address");
    host = `${data[addrIndex]}.${data[addrIndex + 1]}.${data[addrIndex + 2]}.${data[addrIndex + 3]}`;
    addrIndex += 4;
  } else if (addrType === 2) {
    // Domain
    const len = data[addrIndex];
    addrIndex++;
    if (data.length < addrIndex + len) throw new Error("Invalid domain name");
    host = new TextDecoder().decode(data.slice(addrIndex, addrIndex + len));
    addrIndex += len;
  } else if (addrType === 3) {
    // IPv6
    if (data.length < addrIndex + 16) throw new Error("Invalid IPv6 address");
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(
        ((data[addrIndex + i * 2] << 8) + data[addrIndex + i * 2 + 1]).toString(16)
      );
    }
    host = parts.join(":");
    addrIndex += 16;
  } else {
    throw new Error(`Unknown address type: ${addrType}`);
  }

  const rest = data.slice(addrIndex);

  return {
    version,
    host,
    port,
    rest,
  };
}

// ---------------- SSH connection validator ----------------

function isHostAllowed(host: string): boolean {
  if (ALLOWED_SSH_HOSTS.length === 0) return true;
  return ALLOWED_SSH_HOSTS.some(allowed => {
    // Support wildcard pattern
    if (allowed.includes("*")) {
      const pattern = allowed.replace(/\*/g, ".*");
      return new RegExp(`^${pattern}$`).test(host);
    }
    return host === allowed;
  });
}

// ---------------- SSH WebSocket handler ----------------

async function handleSSHWebSocket(req: Request): Promise<Response> {
  const { socket, response } = Deno.upgradeWebSocket(req);
  let connection: Deno.Conn | null = null;
  let keepAliveInterval: number | null = null;

  // Keep connection alive with ping/pong
  keepAliveInterval = setInterval(() => {
    if (socket.readyState === WebSocket.OPEN) {
      try {
        socket.send(new Uint8Array([0x09])); // Ping frame
      } catch {
        // Ignore errors
      }
    }
  }, 30000);

  socket.onopen = () => {
    console.log(`[SSH] New WebSocket connection from ${req.headers.get("x-forwarded-for") || "unknown"}`);
  };

  socket.onmessage = async (event) => {
    try {
      let data: Uint8Array;
      
      if (event.data instanceof ArrayBuffer) {
        data = new Uint8Array(event.data);
      } else if (event.data instanceof Uint8Array) {
        data = event.data;
      } else if (typeof event.data === "string") {
        data = new TextEncoder().encode(event.data);
      } else {
        throw new Error("Unsupported data type");
      }

      // First message handling for connection configuration
      if (!connection) {
        let sshHost = Deno.env.get("SSH_TARGET_HOST") || "localhost";
        let sshPort = parseInt(Deno.env.get("SSH_TARGET_PORT") || "22");
        
        // Try to parse JSON configuration from first message
        try {
          const decoder = new TextDecoder();
          const text = decoder.decode(data);
          const json = JSON.parse(text);
          
          if (json.host) sshHost = json.host;
          if (json.port) sshPort = json.port;
          
          console.log(`[SSH] Connecting to ${sshHost}:${sshPort}`);
        } catch {
          // Not JSON, use defaults or raw SSH data
          console.log(`[SSH] Using default target ${sshHost}:${sshPort}`);
        }
        
        // Validate allowed hosts
        if (!isHostAllowed(sshHost)) {
          throw new Error(`Host ${sshHost} not allowed`);
        }
        
        // Validate port range
        if (sshPort < 1 || sshPort > 65535) {
          throw new Error(`Invalid port: ${sshPort}`);
        }
        
        // Connect to SSH server
        connection = await Deno.connect({
          hostname: sshHost,
          port: sshPort,
          transport: "tcp",
        });
        
        console.log(`[SSH] Connected to ${sshHost}:${sshPort}`);
        
        // Send connection success response
        const successMsg = new TextEncoder().encode(JSON.stringify({ 
          status: "connected", 
          host: sshHost, 
          port: sshPort 
        }));
        socket.send(successMsg);
        
        // Start bidirectional piping
        
        // Remote -> WebSocket
        (async () => {
          const buffer = new Uint8Array(BUFFER_SIZE);
          try {
            while (connection) {
              const n = await connection.read(buffer);
              if (!n) break;
              
              if (socket.readyState === WebSocket.OPEN) {
                socket.send(buffer.slice(0, n));
              } else {
                break;
              }
            }
          } catch (err) {
            console.error("[SSH] Remote read error:", err.message);
          } finally {
            if (socket.readyState === WebSocket.OPEN) {
              socket.close();
            }
            if (connection) {
              connection.close();
              connection = null;
            }
          }
        })();
        
        // Send any remaining data from the first message (if it contained SSH data)
        try {
          JSON.parse(new TextDecoder().decode(data));
          // It was JSON, no raw data to send
        } catch {
          // It was raw SSH data, send it
          if (connection) {
            await connection.write(data);
          }
        }
      } else {
        // Data forwarding
        if (connection && socket.readyState === WebSocket.OPEN) {
          await connection.write(data);
        }
      }
    } catch (err) {
      console.error("[SSH] Handler error:", err.message);
      if (socket.readyState === WebSocket.OPEN) {
        const errorMsg = new TextEncoder().encode(JSON.stringify({ 
          error: err.message 
        }));
        socket.send(errorMsg);
        socket.close();
      }
    }
  };
  
  socket.onclose = () => {
    console.log("[SSH] WebSocket closed");
    if (keepAliveInterval) {
      clearInterval(keepAliveInterval);
    }
    if (connection) {
      connection.close();
      connection = null;
    }
  };
  
  socket.onerror = (error) => {
    console.error("[SSH] WebSocket error:", error);
  };
  
  return response;
}

// ---------------- VLESS WebSocket handler ----------------

async function handleVLESSWebSocket(req: Request): Promise<Response> {
  const { socket, response } = Deno.upgradeWebSocket(req);
  let connection: Deno.Conn | null = null;

  socket.onmessage = async (event) => {
    try {
      let data: Uint8Array;
      
      if (event.data instanceof ArrayBuffer) {
        data = new Uint8Array(event.data);
      } else if (event.data instanceof Uint8Array) {
        data = event.data;
      } else {
        data = new TextEncoder().encode(event.data as string);
      }

      if (data.length > MAX_PAYLOAD_SIZE) {
        throw new Error("Payload too large");
      }

      const vless = await parseVLESSHeader(data);

      connection = await Deno.connect({
        hostname: vless.host,
        port: vless.port,
      });

      // Send response header
      socket.send(new Uint8Array([vless.version, 0]));

      // Send remaining payload
      if (vless.rest.length > 0) {
        await connection.write(vless.rest);
      }

      // Remote -> WebSocket
      (async () => {
        const buffer = new Uint8Array(BUFFER_SIZE);
        try {
          while (connection) {
            const n = await connection.read(buffer);
            if (!n) break;
            
            if (socket.readyState === WebSocket.OPEN) {
              socket.send(buffer.slice(0, n));
            } else {
              break;
            }
          }
        } catch (err) {
          console.error("[VLESS] Remote read error:", err.message);
        } finally {
          if (socket.readyState === WebSocket.OPEN) {
            socket.close();
          }
          if (connection) {
            connection.close();
            connection = null;
          }
        }
      })();

      // WebSocket -> Remote
      socket.onmessage = async (ev) => {
        if (connection) {
          let sendData: Uint8Array;
          if (ev.data instanceof ArrayBuffer) {
            sendData = new Uint8Array(ev.data);
          } else if (ev.data instanceof Uint8Array) {
            sendData = ev.data;
          } else {
            sendData = new TextEncoder().encode(ev.data as string);
          }
          await connection.write(sendData);
        }
      };

    } catch (err) {
      console.error("[VLESS] Handler error:", err.message);
      if (socket.readyState === WebSocket.OPEN) {
        socket.close();
      }
    }
  };

  socket.onclose = () => {
    if (connection) {
      connection.close();
      connection = null;
    }
  };

  return response;
}

// ---------------- Configuration endpoints ----------------

function generateVLESSConfig(): string {
  return `vless://${UUID}@${DOMAIN}:443` +
    `?encryption=none` +
    `&security=tls` +
    `&type=ws` +
    `&host=${DOMAIN}` +
    `&path=/${WS_PATH}` +
    `&sni=${DOMAIN}` +
    `#Railway-VLESS-WS`;
}

function generateSSHConfig(): string {
  return `# SSH over WebSocket Tunnel Configuration
# =========================================

# Method 1: Using websocat
websocat wss://${DOMAIN}/${SSH_PATH} --text ssh://user@ssh-server:22

# Method 2: Using wstunnel
wstunnel client --ws-url wss://${DOMAIN}/${SSH_PATH} -L 2222:localhost:22
# Then connect with: ssh -p 2222 user@localhost

# Method 3: Using custom client
# WebSocket URL: wss://${DOMAIN}/${SSH_PATH}
`;
}

// ---------------- Main server ----------------

serve(
  async (req: Request) => {
    const url = new URL(req.url);
    const upgrade = req.headers.get("upgrade");
    
    // CORS headers for web clients
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };
    
    // Handle preflight
    if (req.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // Root path - Info page
    if (url.pathname === "/") {
      return new Response(
        `<!DOCTYPE html>
<html>
<head>
    <title>SSH/VLESS WebSocket Tunnel</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .endpoint { background: #e8f4f8; padding: 10px; margin: 10px 0; border-left: 3px solid #2196f3; }
    </style>
</head>
<body>
    <h1>🚀 SSH/VLESS WebSocket Tunnel Server</h1>
    <div class="endpoint">
        <strong>VLESS Endpoint:</strong> <code>/${WS_PATH}</code>
    </div>
    <div class="endpoint">
        <strong>SSH Endpoint:</strong> <code>/${SSH_PATH}</code>
    </div>
    <div class="endpoint">
        <strong>Subscription:</strong> <code>/${SUB_PATH}</code>
    </div>
    <h2>SSH Tunnel Usage:</h2>
    <pre>websocat wss://${DOMAIN}/${SSH_PATH} --text ssh://user@ssh-server:22</pre>
    <h2>VLESS Config:</h2>
    <pre>${generateVLESSConfig()}</pre>
</body>
</html>`,
        { headers: { "Content-Type": "text/html", ...corsHeaders } }
      );
    }

    // Subscription endpoint
    if (url.pathname === `/${SUB_PATH}`) {
      const vlessConfig = generateVLESSConfig();
      const configs = [vlessConfig];
      const base64Config = btoa(configs.join("\n"));
      
      return new Response(base64Config, {
        headers: { 
          "Content-Type": "text/plain",
          "Profile-Update-Interval": "24",
          ...corsHeaders
        },
      });
    }
    
    // SSH config endpoint
    if (url.pathname === `/${SSH_PATH}/config`) {
      return new Response(generateSSHConfig(), {
        headers: { "Content-Type": "text/plain", ...corsHeaders },
      });
    }

    // VLESS WebSocket endpoint
    if (url.pathname === `/${WS_PATH}`) {
      if (upgrade !== "websocket") {
        return new Response("WebSocket upgrade required", { status: 400, headers: corsHeaders });
      }
      return handleVLESSWebSocket(req);
    }

    // SSH WebSocket endpoint
    if (url.pathname === `/${SSH_PATH}`) {
      if (upgrade === "websocket") {
        return handleSSHWebSocket(req);
      }
      // Provide info for non-websocket requests
      return new Response(
        `SSH over WebSocket Tunnel Endpoint

WebSocket URL: wss://${DOMAIN}/${SSH_PATH}

Quick Start:
  websocat wss://${DOMAIN}/${SSH_PATH} --text ssh://user@host:22

For configuration details, visit: /${SSH_PATH}/config`,
        { status: 200, headers: { "Content-Type": "text/plain", ...corsHeaders } }
      );
    }

    return new Response("Not Found", { status: 404, headers: corsHeaders });
  },
  { port: PORT },
);

console.log(`✅ Server running on port ${PORT}`);
console.log(`📡 WebSocket endpoints:`);
console.log(`   - VLESS: ws://localhost:${PORT}/${WS_PATH}`);
console.log(`   - SSH: ws://localhost:${PORT}/${SSH_PATH}`);
