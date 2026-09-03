# MCPShield API

Run `npm run start:api`. The default port is `3001`; local state is stored in
`mcpshield.db`. Set `DATABASE_PATH=:memory:` for ephemeral state and
`VALIDATOR_ADDRESSES` to three comma-separated validator addresses.

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

Without chain settings the API reports `ledgerMode: LOCAL_DEMO` and mirrors the
same deterministic state machine in SQLite. For live EVM mode, set `RPC_URL`,
`REGISTRY_ADDRESS`, `DEPLOYER_PRIVATE_KEY`, `VALIDATOR_ADDRESSES`, and three
comma-separated `VALIDATOR_PRIVATE_KEYS`. Admission checks then fail closed if
the current on-chain state cannot be read.
