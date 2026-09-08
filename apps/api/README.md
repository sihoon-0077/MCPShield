# MCPShield API

Run `npm run start:api`. The default port is `3001`; local state is stored in
`mcpshield.db`. Set `DATABASE_PATH=:memory:` for ephemeral state and
`VALIDATOR_ADDRESSES` to three comma-separated validator addresses.
Use `.env.example` as a variable checklist and supply values through your
secret manager or environment; it intentionally contains no usable values.
Startup rejects missing or placeholder admin/scanner credentials, CORS, validator, and EIP-712
domain settings. `POST /api/releases` requires
`Authorization: Bearer $ADMIN_API_TOKEN`.
`POST /api/scans` separately requires
`Authorization: Bearer $SCANNER_API_TOKEN`; the server stamps accepted results
as `LIVE` instead of trusting the submitted source. Scan ingestion has a
256-KiB default body limit and a 30 requests/minute default rate limit.

Endpoints:

- `POST /api/releases`
- `POST /api/scans`
- `GET /api/scans/:scanId`
- `GET /api/releases/:releaseId/scans/latest`
- `GET /api/releases/:releaseId`
- `POST /api/validators/vote`
- `POST /api/admission/check`
- `GET /api/events?releaseId=...`

Set `MCPSHIELD_JUDGE_DEMO_ENABLED=true` to expose the public, fixed-fixture Judge Lab endpoints:

- `POST /api/demo/sessions`
- `GET /api/demo/sessions/:sessionId`
- `POST /api/demo/sessions/:sessionId/actions`
- `DELETE /api/demo/sessions/:sessionId`

Judge sessions live for 15 minutes in one process, accept only the nine fixed actions, and never accept artifact uploads, URLs, credentials, or validator keys. The UI is available at `/try` on the Dashboard. Keep the feature disabled outside the isolated hackathon demo deployment.

Every request payload requires `schemaVersion: "1.0.0"`. Scan results are
validated against the canonical JSON Schemas under `packages/protocol/schemas`.

Validators keep their keys outside the API. `apps/validator` signs an EIP-712
attestation containing release key, decision, evidence hash, nonce, and
deadline. The API recovers the signer, checks the referenced stored scan, then
relays the signature; the contract independently checks signer, nonce, expiry,
and one-vote-per-release replay protection.

Without chain settings the API reports `ledgerMode: LOCAL_DEMO` and mirrors the
same deterministic state machine in SQLite. For live EVM mode, set `RPC_URL`,
`REGISTRY_ADDRESS`, and `RELAYER_PRIVATE_KEY`. The relayer is not a validator
key. Admission reads the full on-chain release under an RPC deadline and fails
closed if status or either artifact hash cannot be verified.

SQLite is intentionally the P0 runtime. The PostgreSQL migration is supplied
for the deployment phase, but a PostgreSQL runtime adapter is not part of this
hackathon build.

`pending_operations` records before-send, submitted tx hash, completion, and
failure states to expose DB/chain partial failures. Run `npm run reconcile` to
check `SUBMITTED` receipts and idempotently rebuild releases, votes, validator
nonces, and status from chain truth. Pending receipts and RPC timeouts stay
`SUBMITTED` for the next run; reverted receipts become `FAILED`.
Registration and attestation endpoints atomically claim their operation ID
before sending. Concurrent retries receive `202` without a second transaction;
completed retries return the existing result. Failed operations are retried
only after the API confirms canonical chain truth.

Typed request interfaces for release registration, scan submission, signed
attestation (including `scanId`, `nonce`, `deadline`, and `signature`), and
admission (including `toolSurfaceHash`) live in
`packages/protocol/api/types.ts`.
# Additive master control plane (`/v1`)

The deployed `/api` demo stays compatible. `/v1` uses exact digest release IDs and explicit tenant credentials; it is disabled unless `CONTROL_PLANE_ENABLED=true`.

```text
CONTROL_PLANE_ENABLED=true
CONTROL_PLANE_CREDENTIALS=[{"tenantId":"your-team","role":"admin","token":"<generated-secret>"}]
CONTROL_DATABASE_URL=postgresql://user:password@postgres:5432/mcpshield
CONTROL_EVIDENCE_KEY=<64 hex characters from randomBytes(32)>
CONTROL_ARTIFACT_PATH=/data/artifacts
CONTROL_EVIDENCE_PATH=/data/evidence
```

`CONTROL_DATABASE_URL` can instead be a SQLite file for one-process development. The v1 PostgreSQL adapter executes the same portable migration against a real pool; legacy `/api` projections still use their SQLite adapter. Encrypted evidence is content-addressed local object storage, with AES-256-GCM and tenant AAD; do not lose the environment encryption key. Object storage must share a volume between API and scan worker.

Run the independently deployable worker with `node --import tsx apps/api/src/control-worker-cli.ts` (add `--once` for one job). It claims durable SQL jobs, retries classified transient failures three times, and puts exhausted work in `DEAD_LETTER`. The worker uses the scanner's safe static-only entrypoint by default. `CONTROL_SANDBOX_MODE=docker` opts into the scanner's actual isolated Docker runtime. Scan completion alone never makes a release VERIFIED.

| Endpoint | Role | Response |
|---|---|---|
| `GET /v1/session` | reader+ | tenant, role, capabilities |
| `GET /v1/releases`, `/v1/policies`, `/v1/scans` | reader+ | `{items:[...]}` |
| `POST /v1/releases/resolve` | operator+ | `{release}`; sourceType npm/tarball/fixture, locator |
| `POST /v1/scans` | operator+ | `{scan,deduplicated,links}`; releaseId,policyHash + Idempotency-Key |
| `GET /v1/scans/:id` | reader+ | `{scan}` |
| `GET /v1/scans/:id/evidence` | operator+ | decrypted Merkle-verified `{bundle,reportRoot}` plus audit event |
| `POST /v1/scans/:id/retry` | operator+ | only retryable DLQ work |
| `GET /v1/releases/:id/history`, `/v1/events` | reader+ | bounded audit events |
| `GET/POST /v1/releases/:id/appeals` | reader/operator+ | reason and optional same-release scanId |
| `POST /v1/appeals/:id/resolve` | admin | resolution text, immutable history retained |
| `POST /v1/policies` | admin | alias + versioned document; hash immutable |
| `POST /v1/policies/:hash/deprecate` | admin | explicit deprecation audit |
| `GET /v1/operations` | reader+ | latest-250 scan counts and actual DB driver |
| `POST /v1/admission/check` | reader+ | policy/identity-bound decision and optional signed snapshot |

Admission body is `{releaseId,artifactDigest,toolSurfaceHash,policyHash,mode:"strict"|"balanced",operationClass:"READ_PUBLIC"|"READ_PRIVATE"|"WRITE_EXTERNAL"|"DESTRUCTIVE"|"FINANCIAL"}`. Runtime identity must use the digest releaseId from resolve, not the legacy name@version. `CONTROL_V2_RPC_URLS`, `CONTROL_V2_REGISTRY_ADDRESS`, `CONTROL_V2_CHAIN_ID`, and optional `CONTROL_V2_CONFIRMATIONS` (default 2) enable the V2 chain reader. It requires confirmed/current agreement for ALLOW and uses the latest chain block to deny quarantine/revocation. Without a V2 reader, admission explicitly BLOCKs with LOCAL_DEMO source.

Set `CONTROL_SIGNING_KEY` to an Ed25519 PKCS8 PEM and `CONTROL_SIGNING_KEY_ID` to publish signed snapshots. The signature covers sorted-key JSON of all fields including tenantId, operationClass, reasonCode and reportUrl; expiry is at most 30 seconds and never exceeds the chain attestation. Gateway must pin the public key and chain coordinates. No signing private key is returned by an endpoint.

Verification: `node --import tsx --test tests/api/control-plane.test.ts tests/contracts/release-registry-v2.test.ts`. Set `MCPSHIELD_POSTGRES_TEST_URL` to run the actual PostgreSQL case (otherwise explicitly skipped). Existing tests are unchanged.

Current boundaries: V2 contracts/reader are separate from V1 and have not been publicly deployed. V2 write relayer/validator fanout and durable chain projection are next integration work; never label a completed off-chain scan VERIFIED. SQL queue is the durable source; Redis stage streams, S3-compatible object replication, richer stage scheduling, PITR and production governance are not implemented by this batch.
# V2 authenticated control plane

The original `/api` demo stays compatible. `/v1` requires a tenant-scoped bearer token;
readers cannot retrieve evidence, operators scan and sign, and admins register chain
identities and publish/deprecate policies. Never expose the relayer or validator keys
to the browser. SQL is the durable queue and transaction outbox (SQLite locally,
PostgreSQL for shared workers); evidence is AES-256-GCM encrypted with tenant AAD.

Run `node --import tsx apps/api/src/control-worker-cli.ts` with the same control-plane
database/evidence/artifact configuration as the API. `--scan-only`, `--chain-only`, and
`--once` select bounded worker modes. The scanner defaults to static-only and returns
`INCONCLUSIVE`/`ABSTAIN`, not a fabricated PASS. A dedicated trusted Linux worker with
Docker may set `CONTROL_SANDBOX_MODE=docker`; do not mount its Docker socket in the API.

V2 chain configuration: `CONTROL_V2_RPC_URLS`, `CONTROL_V2_REGISTRY_ADDRESS`,
`CONTROL_V2_CHAIN_ID`, `CONTROL_V2_CONFIRMATIONS` (default 2),
`CONTROL_V2_DEPLOYMENT_BLOCK`, and the worker/server-only `CONTROL_V2_RELAYER_KEY`.
The first RPC submits transactions; all configured read RPCs can serve admission.
`node --import tsx contracts/scripts/deploy-v2.ts` is a read-only preflight; `--deploy`
is required to spend gas. Deployment also needs `DEPLOYER_PRIVATE_KEY` and three comma-
separated `VALIDATOR_ADDRESSES`. `V2_GOVERNANCE_ADMIN` optionally assigns policy and
validator administration externally; the deployer stays the release-registration relayer.

Workflow: resolve a release, enqueue `/v1/releases/:releaseId/register`, enqueue
`/v1/policies/:policyHash/publish`, submit a scan, await completion, then fetch
`/v1/scans/:scanId/attestation?validator=0x...`. Sign its EIP-712 payload and POST it to
`/v1/validator/attestations`. A deterministic critical report also exposes the
`quarantine` template and `/v1/validator/quarantines`. Poll `/v1/chain/actions/:actionId`;
the same signed request is idempotent. Prepared raw transaction bytes are persisted
before broadcast and retained for identical rebroadcast after uncertain outcomes.
An expiring SQL lease serializes each relayer's nonce stream. Reorg reconciliation
rewinds missing receipts and indexer checkpoints, appending orphan notices to history.

`node --import tsx apps/validator/src/v2.ts` demonstrates two distinct signers after
each independently retrieves and checks the report Merkle root. Supply `CONTROL_API_URL`,
`CONTROL_API_TOKEN`, `CONTROL_SCAN_ID`, and `VALIDATOR_PRIVATE_KEYS` (JSON array) privately.
This convenience command is explicitly `SINGLE_INSTITUTION_DEMO`, not independent organizations.

Validators also require pinned `CONTROL_V2_CHAIN_ID`, `CONTROL_V2_REGISTRY_ADDRESS`,
`CONTROL_V2_RPC_URLS`, and `CONTROL_VALIDATOR_POLICY_HASH`. They reconstruct the local
EIP-712 domain/types, verify evidence/identity/policy/expiry against that trust context,
and check active-validator membership and nonce directly through the configured RPC.
Completion is checked against the exact transaction calldata and successful receipt;
an API-supplied completed flag alone is insufficient. Public HTTP RPC URLs, URL userinfo,
and redirects are rejected. Explicit private hosts may be listed in
`CONTROL_V2_ALLOW_HTTP_HOSTS`; loopback is already allowed. Admission permits at most
three configured RPC endpoints within one 1500 ms total budget, then fails closed.

Remote semantic analysis is disabled unless `CONTROL_ALLOW_REMOTE_AI=true`. For OpenAI,
set `CONTROL_AI_PROVIDER=openai`, `CONTROL_AI_MODEL`, and server-only `OPENAI_API_KEY`
(or `CONTROL_AI_TOKEN`). For an existing compatible service use `CONTROL_AI_PROVIDER=custom`
and `CONTROL_AI_URL`. `CONTROL_AI_TIMEOUT_MS` is bounded to 100–120000 ms. These settings
are never accepted from scan request JSON; provider failures remain labeled fallback evidence.
Keys stay server-side, as required by the [official OpenAI authentication guidance](https://developers.openai.com/api/reference/overview).

Verification: `npm run test:api` and `npm run test:contracts`. The default V2 full-cycle
test runs genuine local EVM transactions with an explicitly labeled report fixture;
`MCPSHIELD_DOCKER_TESTS=1 node --import tsx --test tests/api/v2-fullcycle.test.ts` adds
actual isolated scanning before the same quorum → verified MCP execution → quarantine
→ revocation → two-Gateway pre-spawn blocking flow. No testnet or live AI verification
is implied by those local tests.
