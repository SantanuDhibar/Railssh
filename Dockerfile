# Dockerfile
FROM denoland/deno:alpine-1.40.0

WORKDIR /app

# Copy application files
COPY server.ts .
COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

# Expose port
EXPOSE ${PORT:-3000}

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD deno run --allow-net --allow-env --allow-read https://deno.land/std@0.224.0/http/file_server.ts --check /app || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]
