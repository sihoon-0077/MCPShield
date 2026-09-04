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
