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
