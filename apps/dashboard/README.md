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

### High-risk receipt checkpoints

The optional receipt panel loads tenant ledger and batch metadata on demand. `LOCAL_UNANCHORED`, `SUBMITTED`, `CONFIRMED` (configured confirmation threshold) and `ORPHANED` (canonical reorg invalidated the prior observation) remain separate from the outbox queue status. It displays API-provided chain ID, registry, transaction hash, confirmation count, observation time, root, sequence range and LIVE/MOCK/REPLAY source. A confirmed checkpoint does **not** prove a tool actually executed. A failed refresh hides previous confirmed rows instead of falling back to cached or REPLAY success. Receipt actions are excluded from the release-policy transaction list.

Readers can list metadata. Admins alone may register a nonzero public writer address after acknowledging the target and gas cost; the browser and BFF reject other fields and private-key-length inputs. Address syntax is not proof of ownership. An uncertain response retains the same idempotency key for retry in the current page; after a reload, check existing ledgers before registering again. Actual local-ledger verification, batch upload and writer signing remain in `apps/validator/src/receipt-writer.ts`; the BFF does not expose upload, attestation or anchor submission routes. This panel has no private-key, raw-argument or extra API-key entry field.

Operator/admin evidence queries receive only a BFF-projected root, evidence-file count, verification label and query time. The API decrypts and verifies the Merkle bundle and receipt sequence; raw receipts never reach the browser through this route. The UI says **the API verified the evidence root**, not that the browser independently verified it, and rejects a root mismatch. Unconfigured `CONTROL_RECEIPT_*` returns an error; an empty ledger list does not prove the optional feature is configured. Disable anchoring on the API to stop mutations; closing the panel does not cancel an already queued transaction.

`npm run test:dashboard` includes a real local Ganache → receipt registry → API → BFF test: admin-only idempotent registration, direct writer CLI signing, 1/2 vs 2/2 confirmations, canonical reorg, tenant isolation, reader evidence rejection, summary-only browser responses and RPC outage. SSR tests cover labels and stale-state hiding; they are not interactive browser QA. No real keys or external chain writes are used.

### Connection and existing release workflow

`/console` uses only the additive `/v1` control plane. Configure `MCPSHIELD_API_URL` and the exact `MCPSHIELD_PUBLIC_ORIGIN` on the dashboard, and `CONTROL_PLANE_CREDENTIALS` on the API. Sign in using a token assigned to your tenant and reader/operator/admin role; tokens are exchanged for an HttpOnly SameSite=Strict session cookie, never placed in localStorage or URLs. Production requires an explicit HTTPS public origin and uses a Secure cookie. Forwarded headers do not determine the trusted origin. Existing demo `/`, `/try`, and MCP `/mcp` remain separately available.

For a loopback-only production-build preview, explicitly set `MCPSHIELD_CONTROL_ALLOW_LOOPBACK_HTTP=true` with e.g. `MCPSHIELD_PUBLIC_ORIGIN=http://127.0.0.1:3000`. This exception accepts only `127.0.0.1`, `localhost`, or `[::1]`; it never permits a public HTTP origin. Bind the preview port to loopback and do not use real credentials. Backend HTTP is likewise restricted to loopback unless its exact private hostname is listed in `MCPSHIELD_API_HTTP_HOSTS` (e.g. `backend` for `http://backend:3001` on a private Compose network).

The console supports release registration (npm, tarball, digest-pinned OCI, server-allowlisted fixtures), inventory/search, policy/expiry/digest/chain context, scan submission and dead-letter retry, role-gated evidence, release history and appeals, and immutable policy creation. Scan counts come from the tenant-wide operations API; inventory and transaction lists are limited to the latest 250 loaded records. These are not fleet-wide SLO or throughput claims. An API connection alone is not blockchain proof: a release without chain context displays `체인 증빙 없음`.

Opening a release shows the V2 workflow: scan completion → evidence READY and PASS/FAIL/ABSTAIN recommendation → validator submission records → indexed registry state → an explicit strict admission API query. `READY` is not `PASS`; submission counts are not distinct validators or a quorum; outbox `PREPARED` has not proved broadcast, and `COMPLETED` is a receipt/already-applied result, not finality. A failed index refresh labels preserved chain metadata as historical. Refresh reloads the recorded state; the console does not silently fall back to REPLAY. The separate public demo remains unchanged.

Admins can request the existing `/v1/releases/:id/register` and `/v1/policies/:hash/publish` routes after acknowledging the target and possible gas cost. This only queues a server-relayer transaction. Validator signing stays in the external validator runner: there is no browser key entry, automatic voting endpoint, or shared admin-token substitution. Readers may query admission under their own API permissions. The UI displays the API's source, signed-snapshot presence, expiry and observed block; it does not cryptographically validate a snapshot or execute a tool. The actual Gateway independently rechecks before execution. Unconfigured relayers return an explicit error, never a simulated success.

The backend remains authoritative for tenant isolation, quotas, and roles. The narrow `/api/control/*` proxy only forwards listed `/v1` routes, rejects cross-origin mutations, retains the user's own credential scope, and never substitutes a service admin token. JSON requests are bounded to 64 KiB even without Content-Length; upstream responses are bounded to 4 MiB, with 10-second body/network deadlines and no redirects. Clearing the session or stopping the dashboard disables console access; API credentials can be revoked independently.

Validation: `node --import tsx --test apps/dashboard/test/*.test.*` covers authentication, cookie/origin policies, CSRF, route traversal, bounded bodies, real API → resolver → worker → encrypted evidence → appeal, tenant-isolated durable chain enqueue, role rejection and unsigned LOCAL_DEMO admission. Static-only completion remains INCONCLUSIVE/ABSTAIN and UNVERIFIED. Server-rendered UI tests distinguish submission, completion, historical/unavailable chain state and expired admission, without claiming browser-interaction coverage. `npm run build:dashboard` compiles the console and existing public experiences.

For a disposable synthetic UI preview, run `node --import tsx scripts/demo/control-preview.mts`, then start the dashboard with `MCPSHIELD_API_URL=http://127.0.0.1:4198` and an explicit `MCPSHIELD_PUBLIC_ORIGIN` matching its browser address. The helper prints only fixed synthetic credentials, binds to loopback, creates temporary data, and removes it on graceful shutdown. It does not submit chain attestations or imply a passed sandbox check.
