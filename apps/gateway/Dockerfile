FROM node:22-alpine
WORKDIR /app
COPY apps/gateway/package*.json ./
RUN npm ci --omit=dev
COPY apps/gateway/src ./src
COPY scripts/demo/replay.json ./replay.json
ENV NODE_ENV=production PORT=8787 MCPSHIELD_REPLAY_FILE=/app/replay.json
USER node
EXPOSE 8787
CMD ["node", "src/index.mjs", "serve"]
