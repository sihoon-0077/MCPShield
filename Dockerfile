FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS builder

WORKDIR /app

COPY package.json package-lock.json tsconfig.json ./
COPY apps/dashboard/package.json ./apps/dashboard/package.json
COPY apps/gateway/package.json ./apps/gateway/package.json
COPY scripts/demo/package.json ./scripts/demo/package.json
RUN npm ci --ignore-scripts

COPY . .
RUN npm run build:dashboard && npm prune --omit=dev --ignore-scripts --offline

FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS runner

# Runtime never installs packages. Remove unused global package managers instead of shipping their vulnerable trees.
# The immutable upstream image predates the OpenSSL fix; the image vulnerability gate checks the actual result.
RUN apk upgrade --no-cache libcrypto3 libssl3 \
    && rm -rf /usr/local/lib/node_modules/npm /opt/yarn-v1.22.22 \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/yarn /usr/local/bin/yarnpkg

WORKDIR /app

COPY --from=builder --chown=node:node /app/apps/dashboard/.next/standalone ./
COPY --from=builder --chown=node:node /app/apps/dashboard/.next/static ./apps/dashboard/.next/static
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/package.json ./package.json
COPY --from=builder --chown=node:node /app/package-lock.json ./package-lock.json
COPY --from=builder --chown=node:node /app/apps/api ./apps/api
COPY --from=builder --chown=node:node /app/apps/gateway/src ./apps/gateway/src
COPY --from=builder --chown=node:node /app/packages ./packages
COPY --from=builder --chown=node:node /app/services ./services
COPY --from=builder --chown=node:node /app/database ./database
COPY --from=builder --chown=node:node /app/demo/fixtures ./demo/fixtures
COPY --from=builder --chown=node:node /app/scripts/demo/replay.json ./scripts/demo/replay.json

ENV NODE_ENV=production \
    API_HOST=127.0.0.1 \
    API_PORT=3001 \
    MCPSHIELD_API_URL=http://127.0.0.1:3001 \
    MCPSHIELD_MODE=replay \
    MCPSHIELD_REPLAY_FILE=/app/scripts/demo/replay.json \
    MCPSHIELD_ARTIFACT_DIR=/app/demo/fixtures/mail-mcp-1.0.0 \
    MCPSHIELD_GATEWAY_HOST=127.0.0.1 \
    MCPSHIELD_GATEWAY_PORT=8787 \
    MCPSHIELD_JUDGE_DEMO_ENABLED=true \
    DATABASE_PATH=/tmp/mcpshield.db \
    CORS_ALLOWLIST=https://example.invalid \
    VALIDATOR_ADDRESSES=0x70997970C51812dc3A010C7d01b50e0d17dc79C8,0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC,0x90F79bf6EB2c4f870365E785982E1f101E93b906 \
    ATTESTATION_CHAIN_ID=31337 \
    ATTESTATION_CONTRACT=0x0000000000000000000000000000000000000001

USER node
EXPOSE 3000

CMD ["sh", "-c", "node --import tsx apps/api/src/server.ts & api=$!; node apps/gateway/src/index.mjs serve & gateway=$!; node apps/dashboard/server.js & web=$!; trap 'kill $api $gateway $web' TERM INT; wait -n $api $gateway $web"]
