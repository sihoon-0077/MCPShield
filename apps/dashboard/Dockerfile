FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/dashboard/package.json ./apps/dashboard/package.json
COPY apps/gateway/package.json ./apps/gateway/package.json
COPY scripts/demo/package.json ./scripts/demo/package.json
RUN npm ci --workspace @mcpshield/dashboard --include-workspace-root --ignore-scripts

FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./package.json
COPY apps/dashboard ./apps/dashboard
# The Control BFF verifies prepared downloads with these shared pure modules.
# Their external dependency (ethers) is installed from the root lock above.
COPY packages/contracts-sdk/src/v2-identity.mjs packages/contracts-sdk/src/v2-identity.d.mts ./packages/contracts-sdk/src/
COPY packages/artifact-policy/import-policy.mjs ./packages/artifact-policy/import-policy.mjs
COPY apps/gateway/src/artifact.mjs ./apps/gateway/src/artifact.mjs
COPY services/scanner/src/prepared-binding.mjs services/scanner/src/evidence.mjs ./services/scanner/src/
COPY services/resolver/src/runtime-descriptor.mjs ./services/resolver/src/runtime-descriptor.mjs
RUN npm run build --workspace @mcpshield/dashboard

FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS runner
# Match the root runtime's existing OpenSSL fix; standalone runs without npm/Yarn.
RUN apk upgrade --no-cache libcrypto3 libssl3 \
    && rm -rf /usr/local/lib/node_modules/npm /opt/yarn-v1.22.22 \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/yarn /usr/local/bin/yarnpkg
WORKDIR /app
ENV NODE_ENV=production PORT=3000 HOSTNAME=0.0.0.0 MCPSHIELD_REPLAY_FILE=/app/replay.json
COPY --from=builder --chown=node:node /app/apps/dashboard/.next/standalone ./
COPY --from=builder --chown=node:node /app/apps/dashboard/.next/static ./apps/dashboard/.next/static
COPY --chown=node:node scripts/demo/replay.json ./replay.json
USER node
EXPOSE 3000
CMD ["node", "apps/dashboard/server.js"]
