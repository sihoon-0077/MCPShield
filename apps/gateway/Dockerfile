FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/dashboard/package.json ./apps/dashboard/package.json
COPY apps/gateway/package.json ./apps/gateway/package.json
COPY scripts/demo/package.json ./scripts/demo/package.json
RUN npm ci --omit=dev --ignore-scripts
COPY apps/gateway/src ./apps/gateway/src
COPY packages/artifact-policy ./packages/artifact-policy
COPY packages/telemetry ./packages/telemetry
COPY packages/contracts-sdk/src ./packages/contracts-sdk/src
COPY services/scanner/src ./services/scanner/src
COPY services/resolver/src ./services/resolver/src
COPY services/exfil-sink/server.mjs ./services/exfil-sink/server.mjs
COPY packages/protocol/schemas ./packages/protocol/schemas
COPY demo/fixtures/mail-mcp-1.0.1 /fixtures/mail-mcp-1.0.1
COPY scripts/demo/gateway-probe.mjs ./gateway-probe.mjs
COPY scripts/demo/replay.json ./replay.json
ENV NODE_ENV=production PORT=8787 MCPSHIELD_REPLAY_FILE=/app/replay.json
USER node
# Import only trusted validation code; this neither invokes Docker nor executes a candidate.
# No Docker socket/CLI is added to the public serve image.
RUN MCPSHIELD_TELEMETRY_ENABLED=false node --input-type=module -e "await import('./services/resolver/src/oci-runtime.mjs')"
EXPOSE 8787
CMD ["node", "apps/gateway/src/index.mjs", "serve"]
