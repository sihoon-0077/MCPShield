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

Scan intake atomically checks tenant queue/daily bounds and durable idempotency keys.
A still-valid PASS/FAIL for the same exact release and policy is reused across new
request keys; expired or inconclusive results are rescanned. Key aliases remain bound
to their original request hash. Without an explicit `baselineReleaseId`, intake selects
the most recent previously registered, still-valid `VERIFIED` release of the same tool.
An explicit baseline must belong to that tenant and tool; it is shown on the scan record.
PostgreSQL serializes each tenant with a transaction advisory lock; local SQLite uses
one serialized connection. DLQ retries share the same queue bound.

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

`node --import tsx apps/validator/src/v2.ts` independently reacquires source and reruns
the local scanner before signing; checking a supplied Merkle root alone is insufficient.
Supply `CONTROL_API_URL`, `CONTROL_API_TOKEN`, `CONTROL_SCAN_ID`, and a private
`VALIDATOR_PRIVATE_KEY` for `SINGLE_VALIDATOR`. The optional multi-key
`VALIDATOR_PRIVATE_KEYS` JSON array remains `SINGLE_INSTITUTION_DEMO`, not independent organizations.

Validators also require pinned `CONTROL_V2_CHAIN_ID`, `CONTROL_V2_REGISTRY_ADDRESS`,
`CONTROL_V2_RPC_URLS`, and `CONTROL_VALIDATOR_POLICY_HASH`. They reconstruct the local
EIP-712 domain/types, verify evidence/identity/policy/expiry against that trust context,
and check active-validator membership and nonce directly through the configured RPC.
Completion is checked against the exact transaction calldata and successful receipt;
an API-supplied completed flag alone is insufficient. Public HTTP RPC URLs, URL userinfo,
and redirects are rejected. Explicit private hosts may be listed in
`CONTROL_V2_ALLOW_HTTP_HOSTS`; loopback is already allowed. Admission permits at most
three configured RPC endpoints within one 1500 ms total budget, then fails closed.

Default-policy `/v1` signing requires `VALIDATOR_SOURCES_PATH`, an operator-local JSON
file (max 512 KiB, 128 entries). It has exact shape
`{"schemaVersion":"mcpshield.validator-sources.v1","sources":[{"releaseId":"0x...","sourceType":"local","locator":"/absolute/owned/source"}]}`.
No API response supplies paths, provider URLs, commands, or keys. Local inputs are
new bounded snapshots; npm inputs require exact versions, and tarballs use only the
existing HTTPS npm-registry resolver. Acquired tool/artifact/manifest/surface identity
must match the actual chain record. Content changes at a previously configured path
or registry URL are rejected before execution. OCI catalog entries must be digest-pinned
but cannot sign: current OCI inspection is metadata-only, not a generic runtime test.

If the original report used a baseline, its configured source is also reacquired and
bound to its on-chain identity and tool; missing baselines or different recomputed
package diffs stop signing. Each signer runs the existing scanner with Docker, checks
complete runtime observation and matches the original verdict and deterministic
violation scopes. Missing Docker/source or inconclusive reruns cannot be bypassed.
Default policy still allows its labeled local semantic fallback (recorded as
`LOCAL_STRUCTURED_FALLBACK_V1`); explicit `VALIDATOR_ALLOW_REMOTE_AI`/`VALIDATOR_AI_*`
settings enable that validator's own provider. This legacy profile does not claim the
prepared profile's immutable runtime closure, full dependency coverage or generated
normal/adversarial call coverage. The stricter prepared policy remains separate.
Digest-only root-link receipts use the same private append log described below.

The public legacy `/api` judge demo is unchanged. Portable EVM/OTLP report-fixture
tests sign explicitly in test code; there is no production signer bypass option.
`MCPSHIELD_DOCKER_TESTS=1` enables real source reruns in `source-validator.test.ts`
and V2 fullcycle; without it those runtime assertions are explicitly skipped.

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

## Optional receipt checkpoints (FR407)

`ReceiptAnchorRegistry` is a separate immutable contract. Existing ReleaseRegistryV2,
its address, policy/validator authorization and EIP-712 domain do not change.
It commits an opaque random ledger key, Merkle root, sequence range, prior checkpoint
hashes and registered writer signature. Tenant names, agent/tool identities and receipt
plaintext are never sent on-chain. A checkpoint proves integrity/existence, not safe
execution; batches expose their `LIVE`/`REPLAY`/`MOCK` sources separately.

Enable only with explicit `CONTROL_RECEIPT_RPC_URL`, `CONTROL_RECEIPT_CHAIN_ID`,
`CONTROL_RECEIPT_REGISTRY_ADDRESS`, and private `CONTROL_RECEIPT_RELAYER_KEY`.
`CONTROL_RECEIPT_CONFIRMATIONS` defaults to 2 (range 1–100). No settings means the
additive receipt API returns 503; ordinary V2 admission is unaffected. The relayer
must be the receipt contract's immutable admin for API ledger registration. Writers
are separate keys; neither key is accepted in HTTP request bodies or rendered in UI.

`node --import tsx contracts/scripts/deploy-receipts.ts --deploy` requires the receipt
RPC/chain settings and private `DEPLOYER_PRIVATE_KEY`; optional
`RECEIPT_GOVERNANCE_ADMIN` selects an externally managed registration admin. Omitting
it is labeled `SINGLE_INSTITUTION_DEMO`. No deployment happens without `--deploy`.

API workflow (all routes have `/v1` prefix):

- Admin: `POST /receipt-ledgers`, body `{writer: "0x…"}`, `Idempotency-Key` required.
- Reader: `GET /receipt-ledgers`, `GET /receipt-ledgers/:ledgerKey`.
- Operator: `POST /receipt-ledgers/:ledgerKey/batches`, body `{bundle}` generated by
  Gateway `createBatch`. Registered ledger and previous checkpoint must have N confirmations;
  one consecutive batch (1–127 receipts) can be outstanding at a time.
- Reader: `GET /receipt-ledgers/:ledgerKey/batches`, `GET /receipt-batches/:batchId`.
- Operator: `GET /receipt-batches/:batchId/evidence` and `/attestation`; then
  `POST /receipt-batches/:batchId/anchor`, body `{payload, signature}`. Templates
  bind chain, receipt registry, ledger, root, range, previous tip/root, nonce and deadline.

`LOCAL_UNANCHORED` includes queued/prepared transactions, `SUBMITTED` has been
broadcast/mined but not yet N-deep, `CONFIRMED` requires a fresh canonical receipt,
exact calldata and expected event. `ORPHANED` preserves an observed reorg in audit
history; recovery rebroadcasts identical raw bytes. RPC failure returns 503, never
stale `CONFIRMED`. `queueStatus` is separate: outbox `COMPLETED` means mined, not final.
The receipt indexer can rewind a verified orphan even outside the generic recent-100
reconciliation window. It compares the exact tenant/domain/action/hash/raw bytes/nonce
and decoded payload, rechecks canonical absence, then conditionally updates only an
unleased `COMPLETED` action. Failed or replaced payloads and active leases are untouched.
Same root cannot be reassigned to another tenant, ledger or contract domain. Evidence
uses the existing tenant-bound AES-GCM disk/S3 helper; readers cannot fetch plaintext.

The control worker processes the receipt outbox/indexer unless `--scan-only` is set.
The checkpoint indexer pages history and rechecks canonical receipts; this is an O(n)
polling baseline, not a claim of high-volume historical-indexing throughput. API reads
independently verify canonical state. Losing a writer key requires a newly registered
ledger; no hidden key rotation or ownership override exists.

`node --import tsx apps/validator/src/receipt-writer.ts --submit` uploads and signs a
verified local Gateway ledger using `RECEIPT_LEDGER_PATH`, `RECEIPT_LEDGER_KEY`,
`RECEIPT_FROM_SEQUENCE`, `RECEIPT_TO_SEQUENCE`, `CONTROL_API_URL`, `CONTROL_API_TOKEN`,
receipt RPC/chain/registry/confirmation settings and private `RECEIPT_WRITER_KEY`.
The signing inputs come from local receipts and pinned direct RPC, never API templates.
It reports queued status only; poll the batch endpoint for confirmation. Local tests
use synthetic single-institution keys, not independently operated external writers.

Scan detail responses carry a W3C `traceparent` header. The validator continues it
through `validator.fanout/attest/verify/sign`, sends only `traceparent` on API calls,
and API `validator.accept` accepts a child parent only within that scan's trace.
Outbox migration 008 persists `submission_trace_parent` for `chain.submit`; V2 and
receipt indexers follow the actual transaction's scoped parent and reuse its trace ID
in audit events. Shared telemetry's fixed attribute allowlist still excludes bodies,
signatures, tokens, private keys, baggage and raw exceptions. The real V2 regression
checks these durable trace IDs with exports disabled. `admission.decision` follows
the completed scan only when tenant/release/policy and the fresh chain report root
match an indexed `LIMIT 1` lookup. The outer `admission.check` retains the caller's
request trace; correlation failure never changes the admission decision or adds RPC.
`tests/integration/fullcycle-telemetry.test.ts` runs the actual local EVM regression
in a separate process with official HTTP JSON OTLP exports and final shutdown flush.
It checks exact exported parent relationships and rejects raw tool/credential/baggage
fields. Its bounded loopback receiver is a protocol-contract collector, not a live
production collector or query backend; the scan report fixture is not Docker proof.

## Authenticated invalidation stream

`GET /v1/events/stream` accepts the same bearer credentials, including the reader role.
Use authenticated streaming fetch or a server-side BFF; tokens in query parameters
are not accepted. Each connection/reconnection begins with `event: resync` and
`data: {"type":"RESYNC_REQUIRED","reason":"INITIAL"}`. Changed recent event-ID sets
send the same envelope with reason `EVENTS_CHANGED`; `RECONNECT` requests a new stream.
Refetch existing JSON lists and the latest admission decision after resync.

This is only tenant-scoped UI invalidation: no event payload, tenant name, cursor,
`id`, exact audit ordering, or lossless replay. `Last-Event-ID` is deliberately ignored.
The existing bounded 250-event snapshot is fingerprinted every second; heartbeat
comments arrive after 15 quiet seconds. Connections close after 2 minutes without
changes or 10 minutes total. Snapshot reads time out after 3 seconds; slow consumers
are disconnected instead of queued. Limits are 3 connections per tenant / 32 per
API process, not cluster-wide. Abort, credential revocation and server pre-close
release stream resources. SSE is never chain truth or execution authorization;
Gateway fresh admission checking remains unchanged.

`tests/contracts/receipt-anchor.test.ts` measures local Ganache gas (not money prices);
`tests/api/receipt-anchors.test.ts` exercises real EVM/API/outbox/indexer/CLI, tenant ACL,
signature binding, AES-GCM storage, N-depth, actual snapshot/revert and raw-tx recovery.
## Prepared npm runtime queue

`POST /v1/releases/:sourceReleaseId/prepare` (operator, `Idempotency-Key`) accepts
only `{ "policyHash": "0x..." }` for the separate `restricted-node-docker-v1`
policy. Reader routes are `GET /v1/preparations` and `GET /v1/preparations/:id`;
operators can retry retryable dead-letter jobs at `POST /v1/preparations/:id/retry`.
The immutable source must be a resolved npm/tarball package. Request bodies cannot
choose server paths, images, commands, probe plans, provider endpoints, or keys.

Enable explicitly with `CONTROL_PREPARED_ENABLED=true`, `CONTROL_SANDBOX_MODE=docker`,
`CONTROL_PREPARED_BUILDER_DIGEST=sha256:<approved-local-image-config-id>` and
`CONTROL_PREPARED_ARCHITECTURE=amd64` (or `arm64`). Optional
`CONTROL_PREPARED_BIN_NAME` is an operator setting, not a request field.
Jobs freeze builder/platform and installed collector/observer hashes. A changed
configuration cannot silently resume an older job. Preparation jobs and scans
share tenant queue/daily quotas; a completed preparation's child scan is counted once.

`COMPLETED` means the job finished, not PASS, READY, or VERIFIED. These image IDs
are local Docker-daemon config IDs, not publicly pullable registry digests. Source
records remain unchanged and the legacy policy never approves prepared evidence.
Preparation and regular scan workers use a bounded 20-minute ownership lease;
the source admission limit stays 16 MiB and large/opaque closures may require review.
The preparation worker stores a distinct release plus completed scan atomically only
after evidence/identity checks and a live ownership lease. Missing discovery creates
an INCONCLUSIVE result with no invented release identity. Successful new rows own
their exact local runtime tag; stale leases, validation failures and duplicate-image
jobs clean up only their own tag. An uncertain database commit preserves the image
until ownership is resolved, rather than deleting a possibly committed runtime.

Operators can fetch private evidence at `GET /v1/preparations/:id/evidence` and the
Gateway envelope at `GET /v1/releases/:releaseId/gateway-config`. Both use tenant
AES-GCM evidence and independently recheck commitments. Reader lists never expose
raw tools, descriptors, image tags or evidence storage keys. An export is not admission.
The control worker dispatches this queue only when explicitly enabled. It derives
PASS/FAIL/ABSTAIN from the separate strict policy, not advertised scanner checks.
All 13 coverage/completion checks are required for PASS; missing local image,
explicit AI, independent critic, or complete probes cannot become approval. Regular
rescans use the bound prepared image; cross-profile/baseline mixing is rejected.

Each signing validator must have the exact runtime image on its own Docker daemon
and its own `VALIDATOR_PREPARED_BUILDER_DIGEST`, `VALIDATOR_PREPARED_ARCHITECTURE`,
`VALIDATOR_ALLOW_REMOTE_AI=true`, and `VALIDATOR_AI_PROVIDER` configuration. Set
`VALIDATOR_AI_URL` for a custom provider or `VALIDATOR_AI_MODEL` and
`VALIDATOR_AI_TOKEN` for OpenAI; these are local operator settings, never API input.
Whole-source prepared review is **not** authorized by these provider settings.
The current full-source contract test requires the explicit operator setting
`MCPSHIELD_AI_DISCLOSURE_POLICY=LOCAL_CONTRACT_TEST` in each worker/validator,
`provider=custom`, and an exact numeric loopback URL (`127.0.0.1` or `[::1]`).
The equivalent trusted programmatic fields are `scannerOptions.aiDisclosurePolicy`
and validator `preparedAi.disclosurePolicy`. Neither flag is accepted from an API
caller, inferred from a URL, or enabled by default. Evidence labels this
`PROVIDER_QUALITY_NOT_MEASURED`; remote whole-source disclosure remains forbidden
and cannot produce approval. A privacy-scoped real-provider review is separate work.
The signer independently exports the image closure and reruns the scanner with its
own fresh synthetic probes, analyzer and critic before signing the original root.
Verdict and deterministic violation scopes must agree. The API proposes templates
using a private worker proof but does not have a Docker socket or prove independent
execution. Nonce, deadline and validator-set version are fetched after the rerun.
Set `VALIDATOR_PRIVATE_KEY` for a single operator-owned key: the CLI verifies,
submits one validator's vote, confirms that transaction and exits as `SINGLE_VALIDATOR`.
Other institutions run separately; one vote does not claim quorum. The existing
`VALIDATOR_PRIVATE_KEYS` JSON array is `SINGLE_INSTITUTION_DEMO` for two/three keys.
Both variables together are rejected. No browser key input or key sharing is needed.

`VALIDATOR_VERIFICATION_RECEIPTS_PATH` (default `data/validator-verifications.jsonl`)
stores digest-only original/independent-root links. `LOCAL_VERIFICATION_ONLY` is a
private append log, not OS-enforced append-only/WORM, an immutable chain receipt or independent-organizations
claim. Raw closure bytes and tool definitions remain tenant-encrypted off-chain;
validator evidence downloads alone allow 32 MiB with a 15-second total deadline.
Synthetic worker/signing tests prove contracts and failure handling, not actual
Docker execution or real AI quality. PostgreSQL concurrency coverage runs only
when `MCPSHIELD_POSTGRES_TEST_URL` is explicitly configured.

### OCI preparation policy and configuration

The same protected prepare/retry endpoints accept immutable OCI source releases
only under `restricted-oci-offline-v1`. This exact policy commits
`semanticEvidenceMode: LOCAL_CONTRACT_TEST`; it never represents production-model
quality. The source resolver/importer still limits acquisition/snapshot bytes to
100 MiB. `maxExpandedBytes` limits the sum of layer archives and native export to
512 MiB; it is not a larger download allowance. Node/default policies remain 16 MiB.

OCI is disabled by default. Operator configuration requires `CONTROL_OCI_ENABLED=true`,
`CONTROL_SANDBOX_MODE=docker`, `CONTROL_OCI_ARCHITECTURE=amd64` (or `arm64`),
`CONTROL_OCI_BASE_DIGEST`, `CONTROL_OCI_BASE_CATALOGUE_DIGEST`,
`CONTROL_OCI_TRIVY_DIGEST`, `CONTROL_OCI_DATABASE_DIR` (absolute local directory),
`CONTROL_OCI_DATABASE_DIGEST`, and `CONTROL_OCI_SINK_DIGEST`. Image/catalogue/database
digests must be immutable `sha256:` values. Installed observer/sink bytes are also
frozen into the job configuration; changing configuration never silently retries
with different authority. API callers supply only `policyHash`, never these paths,
images, probes or AI credentials. No Docker socket is needed by the API process.

The additive OCI policy/configuration checkpoint remains fail-closed (`ABSTAIN`)
until the strict scanner policy and independent validator rerun are connected.
Binding, image preparation and job completion alone are not PASS or VERIFIED.
