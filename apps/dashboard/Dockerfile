FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/dashboard/package.json ./apps/dashboard/package.json
COPY apps/gateway/package.json ./apps/gateway/package.json
COPY scripts/demo/package.json ./scripts/demo/package.json
RUN npm ci --workspace @mcpshield/dashboard --include-workspace-root=false

FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./package.json
COPY apps/dashboard ./apps/dashboard
RUN npm run build --workspace @mcpshield/dashboard

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production PORT=3000 HOSTNAME=0.0.0.0 MCPSHIELD_REPLAY_FILE=/app/replay.json
COPY --from=builder --chown=node:node /app/apps/dashboard/.next/standalone ./
COPY --from=builder --chown=node:node /app/apps/dashboard/.next/static ./apps/dashboard/.next/static
COPY --chown=node:node scripts/demo/replay.json ./replay.json
USER node
EXPOSE 3000
CMD ["node", "apps/dashboard/server.js"]
