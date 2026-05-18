// server.ts - Hardcoded configuration
import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

// ==================== HARDCODED CONFIGURATION ====================
const UUID = "f9a1ba12-7187-4b25-a5d5-7bafd82ffb4d";
const DOMAIN = "railssh-production-232f.up.railway.app";
const WS_PATH = "ws";
const SUB_PATH = "sub";
const SSH_PATH = "ssh";
const SSH_SUB_PATH = `${SUB_PATH}/ssh`;
const PORT = parseInt(Deno.env.get("PORT") || "3000", 10);

// SSH Target Configuration
const SSH_TARGET_HOST = "railssh-production-232f.up.railway.app";  // Change this to your SSH server
const SSH_TARGET_PORT = 22;

// SSH WebSocket Authentication (required)
// Set a strong password before deploying (env overrides supported)
const SSH_AUTH_USERNAME = Deno.env.get("SSH_AUTH_USERNAME") || ""; // Optional username for Basic auth
const SSH_AUTH_PASSWORD = Deno.env.get("SSH_AUTH_PASSWORD") || "CHANGE_THIS_PASSWORD";

// Allowed SSH hosts (empty array = allow any)
const ALLOWED_SSH_HOSTS: string[] = []; // Leave empty to allow any host

// Performance settings
const MAX_PAYLOAD_SIZE = 1024 * 1024; // 1MB
const BUFFER_SIZE = 32768; // 32KB

// ==================== UUID Utilities ====================

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

// ==================== VLESS Header Parser ====================

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

// ==================== SSH Connection Validator ====================

function isHostAllowed(host: string): boolean {
  if (ALLOWED_SSH_HOSTS.length === 0) return true;
  return ALLOWED_SSH_HOSTS.some(allowed => {
    if (allowed.includes("*")) {
      const pattern = allowed.replace(/\*/g, ".*");
      return new RegExp(`^${pattern}$`).test(host);
    }
    return host === allowed;
  });
}

// ==================== SSH Authentication ====================

type RequestAuth = {
  authenticated: boolean;
  hasCredentials: boolean;
  error?: string;
};

function isAuthConfigured(): boolean {
  return SSH_AUTH_PASSWORD.trim().length > 0 && SSH_AUTH_PASSWORD !== "CHANGE_THIS_PASSWORD";
}

function timingSafeEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);
  const maxLength = Math.max(aBytes.length, bBytes.length);
  let mismatch = aBytes.length ^ bBytes.length;
  for (let i = 0; i < maxLength; i++) {
    const aByte = aBytes[i] ?? 0;
    const bByte = bBytes[i] ?? 0;
    mismatch |= aByte ^ bByte;
  }
  return mismatch === 0;
}

function validateCredentials(password?: string | null, username?: string | null): boolean {
  if (!isAuthConfigured()) return false;
  if (!password || !timingSafeEqual(password, SSH_AUTH_PASSWORD)) return false;
  if (SSH_AUTH_USERNAME && (!username || !timingSafeEqual(username, SSH_AUTH_USERNAME))) return false;
  return true;
}

function parseBasicAuth(authHeader: string): { username: string; password: string } | null {
  const [scheme, value] = authHeader.split(/\s+/, 2);
  if (!scheme || !value || scheme.toLowerCase() !== "basic") return null;
  try {
    const decoded = atob(value);
    const separatorIndex = decoded.indexOf(":");
    if (separatorIndex === -1) {
      return { username: decoded, password: "" };
    }
    return {
      username: decoded.slice(0, separatorIndex),
      password: decoded.slice(separatorIndex + 1),
    };
  } catch {
    return null;
  }
}

function getRequestAuth(req: Request): RequestAuth {
  if (!isAuthConfigured()) {
    return {
      authenticated: false,
      hasCredentials: false,
      error: "SSH password not configured. Set SSH_AUTH_PASSWORD (env or server.ts).",
    };
  }

  const authHeader = req.headers.get("authorization");
  if (authHeader) {
    const [scheme, value] = authHeader.split(/\s+/, 2);
    const normalizedScheme = scheme?.toLowerCase();
    if (!value || !normalizedScheme) {
      return { authenticated: false, hasCredentials: true, error: "Invalid Authorization header." };
    }
    if (normalizedScheme === "basic") {
      const parsed = parseBasicAuth(authHeader);
      if (!parsed || !validateCredentials(parsed.password, parsed.username)) {
        return { authenticated: false, hasCredentials: true, error: "Invalid SSH credentials." };
      }
      return { authenticated: true, hasCredentials: true };
    }
    if (normalizedScheme === "bearer") {
      if (!validateCredentials(value, null)) {
        return { authenticated: false, hasCredentials: true, error: "Invalid SSH credentials." };
      }
      return { authenticated: true, hasCredentials: true };
    }
    return { authenticated: false, hasCredentials: true, error: "Unsupported Authorization scheme." };
  }

  const url = new URL(req.url);
  const token =
    url.searchParams.get("token") ||
    url.searchParams.get("password") ||
    url.searchParams.get("auth");
  const username =
    url.searchParams.get("username") || url.searchParams.get("user");

  if (token) {
    if (!validateCredentials(token, username)) {
      return { authenticated: false, hasCredentials: true, error: "Invalid SSH credentials." };
    }
    return { authenticated: true, hasCredentials: true };
  }

  return { authenticated: false, hasCredentials: false };
}

function parseJsonPayload(data: Uint8Array): Record<string, unknown> | null {
  try {
    const text = new TextDecoder().decode(data);
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object") {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // ignore
  }
  return null;
}

function coerceString(value: unknown): string | null {
  if (typeof value === "string" && value.trim().length > 0) {
    return value;
  }
  return null;
}

function coercePort(portValue: unknown): number | null {
  if (typeof portValue === "number" && Number.isFinite(portValue)) {
    return Math.trunc(portValue);
  }
  if (typeof portValue === "string") {
    const parsed = Number.parseInt(portValue, 10);
    if (!Number.isNaN(parsed)) return parsed;
  }
  return null;
}

function getPasswordPlaceholder(): string {
  return isAuthConfigured() ? "YOUR_PASSWORD_HERE" : "SET_SSH_AUTH_PASSWORD";
}

function getUsernamePlaceholder(): string {
  return SSH_AUTH_USERNAME || "USERNAME";
}

// ==================== SSH WebSocket Handler ====================

async function handleSSHWebSocket(req: Request): Promise<Response> {
  const { socket, response } = Deno.upgradeWebSocket(req);
  let connection: Deno.Conn | null = null;
  let keepAliveInterval: number | null = null;
  const initialAuth = getRequestAuth(req);
  let authenticated = initialAuth.authenticated;

  const sendJsonMessage = (payload: Record<string, unknown>) => {
    if (socket.readyState === WebSocket.OPEN) {
      const message = new TextEncoder().encode(JSON.stringify(payload));
      socket.send(message);
    }
  };

  const sendAuthError = (message: string) => {
    console.error(`[SSH] Auth error: ${message}`);
    if (socket.readyState === WebSocket.OPEN) {
      sendJsonMessage({ error: message });
      socket.close();
    }
  };

  // Keep connection alive with ping/pong
  keepAliveInterval = setInterval(() => {
    if (socket.readyState === WebSocket.OPEN) {
      try {
        socket.send(new Uint8Array([0x09]));
      } catch {
        // Ignore errors
      }
    }
  }, 30000);

  socket.onopen = () => {
    console.log(`[SSH] New WebSocket connection`);
    if (!isAuthConfigured()) {
      sendAuthError("SSH authentication is not configured. Set SSH_AUTH_PASSWORD (env or server.ts).");
      return;
    }
    if (initialAuth.hasCredentials && !authenticated) {
      sendAuthError(initialAuth.error || "Invalid SSH credentials.");
    }
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
        if (!isAuthConfigured()) {
          sendAuthError("SSH authentication is not configured. Set SSH_AUTH_PASSWORD (env or server.ts).");
          return;
        }
        if (initialAuth.hasCredentials && !authenticated) {
          sendAuthError(initialAuth.error || "Invalid SSH credentials.");
          return;
        }

        const jsonPayload = parseJsonPayload(data);

        if (!authenticated) {
          if (!jsonPayload) {
            sendAuthError(
              "Authentication required. Provide Authorization header, query token, or JSON {\"password\":\"...\"}."
            );
            return;
          }

          const password =
            coerceString(jsonPayload.password) ||
            coerceString(jsonPayload.token) ||
            coerceString(jsonPayload.auth);
          const username =
            coerceString(jsonPayload.username) ||
            coerceString(jsonPayload.user);

          if (!validateCredentials(password, username)) {
            sendAuthError("Invalid SSH credentials.");
            return;
          }
          authenticated = true;
        }

        let sshHost = SSH_TARGET_HOST;
        let sshPort = SSH_TARGET_PORT;

        if (jsonPayload) {
          const requestedHost = coerceString(jsonPayload.host);
          const requestedPort = coercePort(jsonPayload.port);
          if (requestedHost) sshHost = requestedHost;
          if (requestedPort) sshPort = requestedPort;
        }

        console.log(`[SSH] Connecting to ${sshHost}:${sshPort}`);

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
        sendJsonMessage({
          status: "connected",
          host: sshHost,
          port: sshPort,
        });

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

        // Send any remaining data from the first message (raw SSH payload)
        if (!jsonPayload && connection) {
          await connection.write(data);
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
        sendJsonMessage({ error: err.message });
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

// ==================== VLESS WebSocket Handler ====================

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

// ==================== Configuration Generators ====================

function generateVLESSConfig(): string {
  return `vless://${UUID}@${DOMAIN}:443` +
    `?encryption=none` +
    `&security=tls` +
    `&type=ws` +
    `&host=${DOMAIN}` +
    `&path=/${WS_PATH}` +
    `&sni=${DOMAIN}` +
    `#Hardcoded-VLESS-WS`;
}

function generateSSHConfig(): string {
  const wsUrl = `wss://${DOMAIN}/${SSH_PATH}`;
  const passwordValue = getPasswordPlaceholder();
  const authStatus = isAuthConfigured() ? "configured" : "not configured";
  const usernameLabel = SSH_AUTH_USERNAME || "(optional)";
  const usernameValue = getUsernamePlaceholder();
  const basicAuth = btoa(`${usernameValue}:${passwordValue}`);
  return `# SSH over WebSocket Tunnel Configuration
# =========================================

# WebSocket URL: ${wsUrl}
# Default Target: ${SSH_TARGET_HOST}:${SSH_TARGET_PORT}

# Authentication (required)
# Username: ${usernameLabel}
# Password: ${passwordValue} (${authStatus})
# Password is configured server-side and is not printed here.
# Header (Bearer): Authorization: Bearer ${passwordValue}
# Header (Basic): Authorization: Basic ${basicAuth}
# Query: ${wsUrl}?token=${passwordValue}
# JSON first message: {"password":"${passwordValue}","host":"${SSH_TARGET_HOST}","port":${SSH_TARGET_PORT}}

# Method 1: Using websocat (Bearer auth)
websocat -H "Authorization: Bearer ${passwordValue}" ${wsUrl} --text ssh://${SSH_TARGET_HOST}:${SSH_TARGET_PORT}

# Method 2: Using wstunnel
wstunnel client --ws-url ${wsUrl} --header "Authorization: Bearer ${passwordValue}" -L 2222:${SSH_TARGET_HOST}:${SSH_TARGET_PORT}
# Then connect with: ssh -p 2222 user@localhost

# Method 3: Using custom client
# WebSocket URL: ${wsUrl}
# First message JSON: {"password":"${passwordValue}","host":"${SSH_TARGET_HOST}","port":${SSH_TARGET_PORT}}
`;
}

function generateSSHSubscription(): string {
  const wsUrl = `wss://${DOMAIN}/${SSH_PATH}`;
  const passwordValue = getPasswordPlaceholder();
  const authStatus = isAuthConfigured() ? "configured" : "not configured";
  const usernameValue = SSH_AUTH_USERNAME || "(optional)";
  const usernameExample = getUsernamePlaceholder();
  const basicAuth = btoa(`${usernameExample}:${passwordValue}`);

  return `# SSH over WebSocket Subscription
# =========================================

ws_url: ${wsUrl}
target: ${SSH_TARGET_HOST}:${SSH_TARGET_PORT}

auth:
  username: ${usernameValue}
  password: ${passwordValue} (${authStatus})
  bearer: ${passwordValue}
  basic: ${basicAuth}

# Password is configured server-side and is not printed here.

# JSON handshake example:
{"password":"${passwordValue}","host":"${SSH_TARGET_HOST}","port":${SSH_TARGET_PORT}}

# websocat example:
websocat -H "Authorization: Bearer ${passwordValue}" ${wsUrl}

# darktunnel example:
# Configure your darktunnel client to use ${wsUrl}
# and send header: Authorization: Bearer ${passwordValue}
# Then forward local port 2222 to ${SSH_TARGET_HOST}:${SSH_TARGET_PORT}
`;
}

// ==================== Main Server ====================

console.log("=".repeat(60));
console.log("🚀 SSH/VLESS WebSocket Tunnel Server (Hardcoded)");
console.log("=".repeat(60));
console.log(`📡 Server Configuration:`);
console.log(`   - Port: ${PORT}`);
console.log(`   - Domain: ${DOMAIN}`);
console.log(`   - VLESS Path: /${WS_PATH}`);
console.log(`   - SSH Path: /${SSH_PATH}`);
console.log(`   - Subscription Path: /${SUB_PATH}`);
console.log(`   - SSH Subscription Path: /${SSH_SUB_PATH}`);
console.log(`   - SSH Target: ${SSH_TARGET_HOST}:${SSH_TARGET_PORT}`);
console.log(`   - VLESS UUID: ${UUID}`);
console.log(`   - Allowed Hosts: ${ALLOWED_SSH_HOSTS.length ? ALLOWED_SSH_HOSTS.join(", ") : "any"}`);
console.log(`   - SSH Auth: ${isAuthConfigured() ? "enabled" : "not configured"}`);
console.log(`   - SSH Auth Username: ${SSH_AUTH_USERNAME || "not set"}`);
console.log("=".repeat(60));
console.log("✅ Server starting...");
console.log("=".repeat(60));

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
        body { font-family: 'Courier New', monospace; max-width: 900px; margin: 50px auto; padding: 20px; background: #0a0e27; color: #00ff9d; }
        h1 { color: #00ff9d; border-bottom: 2px solid #00ff9d; }
        h2 { color: #ff9d00; margin-top: 30px; }
        .endpoint { background: #1a1e3a; padding: 15px; margin: 15px 0; border-left: 3px solid #00ff9d; border-radius: 5px; }
        .endpoint code { color: #ff9d00; }
        pre { background: #1a1e3a; padding: 15px; border-radius: 5px; overflow-x: auto; border: 1px solid #00ff9d33; }
        .status { color: #00ff9d; font-weight: bold; }
        .warning { color: #ff9d00; }
    </style>
</head>
<body>
    <h1>🔒 SSH/VLESS WebSocket Tunnel Server</h1>
    <p class="status">✅ Server is running (Hardcoded Configuration)</p>
    
    <div class="endpoint">
        <strong>📡 VLESS Endpoint:</strong> <code>/${WS_PATH}</code><br>
        <strong>🔑 UUID:</strong> <code>${UUID}</code>
    </div>
    
    <div class="endpoint">
        <strong>🔌 SSH Endpoint:</strong> <code>/${SSH_PATH}</code><br>
        <strong>🎯 Default Target:</strong> <code>${SSH_TARGET_HOST}:${SSH_TARGET_PORT}</code>
    </div>
    
    <div class="endpoint">
        <strong>📥 Subscription:</strong> <code>/${SUB_PATH}</code>
    </div>
    
    <div class="endpoint">
        <strong>📥 SSH Subscription:</strong> <code>/${SSH_SUB_PATH}</code>
    </div>
    
    <h2>🚀 Quick Start - SSH Tunnel</h2>
    <pre>websocat -H "Authorization: Bearer ${getPasswordPlaceholder()}" wss://${DOMAIN}/${SSH_PATH} --text ssh://user@${SSH_TARGET_HOST}:${SSH_TARGET_PORT}</pre>
    
    <h2>📦 VLESS Configuration</h2>
    <pre>${generateVLESSConfig()}</pre>
    
    <h2>📝 Notes</h2>
    <pre>• Update SSH auth in server.ts (env overrides supported for SSH_AUTH_*)
• SSH WebSocket requires password auth (SSH_AUTH_PASSWORD)
• Use Authorization header, query token, or JSON handshake for SSH auth
• SSH connections tunneled through WebSocket
• VLESS proxy for additional protocol support
• Modify SSH_TARGET_HOST and SSH_TARGET_PORT in source code to change targets</pre>
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

    // SSH subscription endpoint
    if (url.pathname === `/${SSH_SUB_PATH}`) {
      return new Response(generateSSHSubscription(), {
        headers: { "Content-Type": "text/plain", ...corsHeaders },
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
Default Target: ${SSH_TARGET_HOST}:${SSH_TARGET_PORT}
Authentication: required (set SSH_AUTH_PASSWORD env or server.ts)

Auth options:
  - Authorization: Bearer ${getPasswordPlaceholder()}
  - Authorization: Basic <base64(username:${getPasswordPlaceholder()})>
  - Query: ?token=${getPasswordPlaceholder()} or ?password=${getPasswordPlaceholder()}
  - JSON handshake: {"password":"${getPasswordPlaceholder()}","host":"${SSH_TARGET_HOST}","port":${SSH_TARGET_PORT}}

Quick Start:
  websocat -H "Authorization: Bearer <password>" wss://${DOMAIN}/${SSH_PATH} --text ssh://user@${SSH_TARGET_HOST}:${SSH_TARGET_PORT}

For configuration details, visit: /${SSH_PATH}/config`,
        { status: 200, headers: { "Content-Type": "text/plain", ...corsHeaders } }
      );
    }

    return new Response("Not Found", { status: 404, headers: corsHeaders });
  },
  { port: PORT },
);

console.log(`✨ Server running on http://localhost:${PORT}`);
console.log(`🌐 WebSocket endpoints:`);
console.log(`   - VLESS: ws://localhost:${PORT}/${WS_PATH}`);
console.log(`   - SSH: ws://localhost:${PORT}/${SSH_PATH}`);
console.log(`   - Subscription: http://localhost:${PORT}/${SUB_PATH}`);
console.log(`   - SSH Subscription: http://localhost:${PORT}/${SSH_SUB_PATH}`);
console.log("=".repeat(60));
