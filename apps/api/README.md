# MCPShield API

Run `npm run start:api`. The default port is `3001`; local state is stored in
`mcpshield.db`. Set `DATABASE_PATH=:memory:` for ephemeral state and
`VALIDATOR_ADDRESSES` to three comma-separated validator addresses.
Copy `.env.example` values into your secret manager or environment and replace
all placeholders. Startup rejects missing admin, CORS, validator, and EIP-712
domain settings. `POST /api/releases` requires
`Authorization: Bearer $ADMIN_API_TOKEN`.

Endpoints:

- `POST /api/releases`
- `POST /api/scans`
- `GET /api/scans/:scanId`
- `GET /api/releases/:releaseId`
- `POST /api/validators/vote`
- `POST /api/admission/check`
- `GET /api/events?releaseId=...`

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
failure states to expose DB/chain partial failures. A production deployment
should add a reconciliation worker for operations left in `SUBMITTED`; retries
are idempotently keyed by release ID or attestation signature.
