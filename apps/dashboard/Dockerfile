FROM node:22-alpine AS deps
WORKDIR /app
COPY apps/dashboard/package*.json ./
RUN npm ci

FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY apps/dashboard ./
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production PORT=3000 HOSTNAME=0.0.0.0 MCPSHIELD_REPLAY_FILE=/app/replay.json
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY scripts/demo/replay.json ./replay.json
USER node
EXPOSE 3000
CMD ["node", "server.js"]
