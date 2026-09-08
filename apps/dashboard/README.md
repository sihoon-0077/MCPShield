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

`/console` uses only the additive `/v1` control plane. Configure `MCPSHIELD_API_URL` and the exact `MCPSHIELD_PUBLIC_ORIGIN` on the dashboard, and `CONTROL_PLANE_CREDENTIALS` on the API. Sign in using a token assigned to your tenant and reader/operator/admin role; tokens are exchanged for an HttpOnly SameSite=Strict session cookie, never placed in localStorage or URLs. Production requires an explicit HTTPS public origin and uses a Secure cookie. Forwarded headers do not determine the trusted origin. Existing demo `/`, `/try`, and MCP `/mcp` remain separately available.

For a loopback-only production-build preview, explicitly set `MCPSHIELD_CONTROL_ALLOW_LOOPBACK_HTTP=true` with e.g. `MCPSHIELD_PUBLIC_ORIGIN=http://127.0.0.1:3000`. This exception accepts only `127.0.0.1`, `localhost`, or `[::1]`; it never permits a public HTTP origin. Bind the preview port to loopback and do not use real credentials. Backend HTTP is likewise restricted to loopback unless its exact private hostname is listed in `MCPSHIELD_API_HTTP_HOSTS` (e.g. `backend` for `http://backend:3001` on a private Compose network).

The console supports release registration (npm, tarball, digest-pinned OCI, server-allowlisted fixtures), inventory/search, policy/expiry/digest/chain context, scan submission and dead-letter retry, role-gated evidence, release history and appeals, and immutable policy creation. Scan counts come from the tenant-wide operations API; inventory and transaction lists are limited to the latest 250 loaded records. These are not fleet-wide SLO or throughput claims. An API connection alone is not blockchain proof: a release without chain context displays `체인 증빙 없음`.

Opening a release shows the V2 workflow: scan completion → evidence READY and PASS/FAIL/ABSTAIN recommendation → validator submission records → indexed registry state → an explicit strict admission API query. `READY` is not `PASS`; submission counts are not distinct validators or a quorum; outbox `PREPARED` has not proved broadcast, and `COMPLETED` is a receipt/already-applied result, not finality. A failed index refresh labels preserved chain metadata as historical. Refresh reloads the recorded state; the console does not silently fall back to REPLAY. The separate public demo remains unchanged.

Admins can request the existing `/v1/releases/:id/register` and `/v1/policies/:hash/publish` routes after acknowledging the target and possible gas cost. This only queues a server-relayer transaction. Validator signing stays in the external validator runner: there is no browser key entry, automatic voting endpoint, or shared admin-token substitution. Readers may query admission under their own API permissions. The UI displays the API's source, signed-snapshot presence, expiry and observed block; it does not cryptographically validate a snapshot or execute a tool. The actual Gateway independently rechecks before execution. Unconfigured relayers return an explicit error, never a simulated success.

The backend remains authoritative for tenant isolation, quotas, and roles. The narrow `/api/control/*` proxy only forwards listed `/v1` routes, rejects cross-origin mutations, retains the user's own credential scope, and never substitutes a service admin token. JSON requests are bounded to 64 KiB even without Content-Length; upstream responses are bounded to 4 MiB, with 10-second body/network deadlines and no redirects. Clearing the session or stopping the dashboard disables console access; API credentials can be revoked independently.

Validation: `node --import tsx --test apps/dashboard/test/*.test.*` covers authentication, cookie/origin policies, CSRF, route traversal, bounded bodies, real API → resolver → worker → encrypted evidence → appeal, tenant-isolated durable chain enqueue, role rejection and unsigned LOCAL_DEMO admission. Static-only completion remains INCONCLUSIVE/ABSTAIN and UNVERIFIED. Server-rendered UI tests distinguish submission, completion, historical/unavailable chain state and expired admission, without claiming browser-interaction coverage. `npm run build:dashboard` compiles the console and existing public experiences.

For a disposable synthetic UI preview, run `node --import tsx scripts/demo/control-preview.mts`, then start the dashboard with `MCPSHIELD_API_URL=http://127.0.0.1:4198` and an explicit `MCPSHIELD_PUBLIC_ORIGIN` matching its browser address. The helper prints only fixed synthetic credentials, binds to loopback, creates temporary data, and removes it on graceful shutdown. It does not submit chain attestations or imply a passed sandbox check.
