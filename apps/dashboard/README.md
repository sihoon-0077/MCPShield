# MCPShield Dashboard

```powershell
npm.cmd ci
npm.cmd run dev --workspace @mcpshield/dashboard
```

Open `http://localhost:3000`. MOCK works without a backend. LIVE reads releases, latest scans, and events. In Compose it also validates Gateway A/B's shared pre-spawn probe evidence; without that configured evidence directory, Backend admission results are explicitly labeled as Backend results rather than Gateway execution. On timeout or malformed data it switches to a clearly labeled REPLAY snapshot and emits an accessible error alert.

Set `MCPSHIELD_API_URL` for LIVE, `MCPSHIELD_REPLAY_FILE` for an alternate replay bundle, `MCPSHIELD_GATEWAY_EVIDENCE_DIR` for Gateway probe files, and optionally `MCPSHIELD_EXPLORER_URL` for EVM transaction links. LIVE automatically reads `GET /api/releases/:releaseId/scans/latest`, so every new random scanner result replaces the displayed evidence without configuration. Unconfigured or invalid explorer URLs are never rendered as links.

`lib/backend-client.ts` is the server-only integration boundary for all seven frozen Backend APIs: release register/get, scan submit/get, validator vote, admission check, and event listing. The dashboard view intentionally calls only read/admission operations; privileged mutations remain available to the demo seeder and scanner rather than browser code, so admin/scanner credentials are never bundled into the client.

Roll back by selecting MOCK/REPLAY or stopping the dashboard container.

## Tenant operations console

`/console` uses only the additive `/v1` control plane. Configure `MCPSHIELD_API_URL` on the dashboard and `CONTROL_PLANE_CREDENTIALS` on the API. Sign in using a token assigned to your tenant and reader/operator/admin role; tokens are exchanged for an HttpOnly SameSite=Strict session cookie, never placed in localStorage or URLs. Use HTTPS for deployments; the session cookie is Secure on HTTPS (including a trusted reverse proxy's `X-Forwarded-Proto: https`). Existing demo `/`, `/try`, and MCP `/mcp` remain separately available.

The console supports release registration (npm, tarball, server-allowlisted fixtures), inventory/search, policy/expiry/digest/chain context, scan submission and dead-letter retry, role-gated evidence, release history and appeals, and immutable policy creation. Counts are explicitly the currently loaded records (backend maximum 250 recent scans); these are not fleet-wide SLO or throughput claims. An API connection alone is not blockchain proof: a release without chain context displays `체인 증빙 없음`.

The backend remains authoritative for tenant isolation, quotas, and roles. The narrow `/api/control/*` proxy only forwards listed `/v1` routes, rejects cross-origin mutations, retains the user's own credential scope, and never substitutes a service admin token. Clearing the session or stopping the dashboard disables console access; API credentials can be revoked independently.

Validation: `node --import tsx --test apps/dashboard/test/control.test.ts` covers authentication, cookie flags, CSRF, route traversal, and propagated evidence authorization. `npm run build:dashboard` compiles the console and existing public experiences.
