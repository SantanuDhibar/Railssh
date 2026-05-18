# Dockerfile - Hardcoded version
FROM denoland/deno:alpine-1.40.0

WORKDIR /app

# Copy the hardcoded server file
COPY server.ts .

# Expose port 3000
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD deno run --allow-net --allow-read https://deno.land/std@0.224.0/http/file_server.ts --check /app || exit 1

# Run the server with necessary permissions
CMD ["deno", "run", "--allow-net", "--allow-read", "--allow-write", "server.ts"]
