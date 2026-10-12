# ==============================================================================
# AEGIS IP INTELLIGENCE - PRODUCTION DOCKERFILE
# ==============================================================================

FROM node:22-alpine AS base

# Install curl for container health check
RUN apk add --no-cache curl

WORKDIR /app

# Set production environment
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0
ENV DATA_DIR=/app/data

# Copy package descriptors and install only production dependencies
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy source code and config templates
COPY src/ ./src/
COPY test-keys.js ./
COPY README.md ./

# Create data directory and tmp folder with proper permissions for non-root user
RUN mkdir -p /app/data/tmp && chown -R node:node /app

# Switch to non-root user for security
USER node

# Expose API port
EXPOSE 3000

# Health check to monitor container health
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start Fastify server
CMD ["node", "src/server.js"]
