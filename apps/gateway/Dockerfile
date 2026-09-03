FROM node:22-alpine
WORKDIR /app
COPY apps/gateway/src ./apps/gateway/src
COPY packages/artifact-policy ./packages/artifact-policy
COPY demo/fixtures/mail-mcp-1.0.1 /fixtures/mail-mcp-1.0.1
COPY scripts/demo/gateway-probe.mjs ./gateway-probe.mjs
COPY scripts/demo/replay.json ./replay.json
ENV NODE_ENV=production PORT=8787 MCPSHIELD_REPLAY_FILE=/app/replay.json
USER node
EXPOSE 8787
CMD ["node", "apps/gateway/src/index.mjs", "serve"]
