# ==============================================================================
# Learnsphere Production Dockerfile
# ==============================================================================
FROM node:20-alpine AS runner

# Install wget for healthcheck
RUN apk add --no-cache wget

WORKDIR /usr/src/app

# Set production environment
ENV NODE_ENV=production
ENV PORT=5000

# Install dependencies first for optimal caching
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy application source code and web assets
COPY server.js ./
COPY index.html ./
COPY courses.html ./
COPY pmp-details.html ./
COPY admin.html ./

# Use unprivileged node user
USER node

# Expose server port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5000/health || exit 1

# Start server
CMD ["node", "server.js"]
