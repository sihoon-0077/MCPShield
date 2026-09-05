# MCPShield Interface Contract v1

All JSON payloads use `schemaVersion: "1.0.0"`. Canonical JSON Schemas live in `packages/protocol/schemas`; TypeScript types live in `packages/protocol/api/types.ts`. Unknown fields are rejected where a shared schema is used.

## Identity formats

| Field | Format |
|---|---|
| `releaseId` | name plus semantic version, e.g. `mail-mcp@1.0.0` |
| `artifactDigest` | `sha256:` plus 64 lowercase hex characters |
| `toolSurfaceHash` | `0x` plus 64 lowercase hex characters |
| `evidenceHash` | `0x` plus 64 hex characters |
| `scanId` | UUID |

## API

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| `GET` | `/health` | none | service and ledger mode |
| `POST` | `/api/releases` | admin bearer token | register exact release identity |
| `POST` | `/api/scans` | scanner bearer token | ingest schema-valid scan; source is forced to `LIVE` |
| `GET` | `/api/scans/:scanId` | none | retrieve scan and evidence summary |
| `GET` | `/api/releases/:releaseId/scans/latest` | none | retrieve the latest stored scan for a release |
| `GET` | `/api/releases/:releaseId` | none | retrieve projected release status and votes |
| `POST` | `/api/validators/vote` | EIP-712 signature | relay a validator decision |
| `POST` | `/api/admission/check` | none | decide `ALLOW` or `BLOCK` for exact identity |
| `GET` | `/api/events?releaseId=` | none | ordered audit events |

## Scan result

Required fields are `scanId`, full release identity, `scanStatus`, `findings`, `evidenceHash`, and `source`. Finding codes are:

- `SENSITIVE_FILE_READ`
- `UNDECLARED_EGRESS`
- `CANARY_EXFILTRATION`
- `TOOL_SURFACE_CHANGED`
- `SEMANTIC_BEHAVIOR_MISMATCH`

Stages are `STATIC`, `AI`, `SANDBOX`, or `POLICY`. AI output must conform to the same bounded Finding shape and cannot directly alter chain state.

The latest-scan endpoint returns `{ "schemaVersion": "1.0.0", "scan": <ScanResult> }`.
It returns `404 SCAN_NOT_FOUND` when that release has no stored scan.

## Validator attestation

The EIP-712 domain is:

```text
name: MCPShield
version: 1
chainId: configured network
verifyingContract: deployed ReleaseRegistry
```

The signed `Attestation` contains:

```text
releaseKey: bytes32 keccak256(releaseId)
decision: uint8 (PASS=0, FAIL=1, ABSTAIN=2)
evidenceHash: bytes32
nonce: uint256
deadline: uint256
```

The HTTP request additionally carries `releaseId` and `scanId` so the Backend can bind the signature to a stored scan before relay.

## Admission decision

The request must contain the exact `releaseId`, `artifactDigest`, and `toolSurfaceHash`. A response contains:

- `decision`: `ALLOW` or `BLOCK`
- `releaseStatus`: `UNVERIFIED`, `VERIFIED`, `QUARANTINED`, or `REVOKED`
- `reasonCode`: status-specific code, `DIGEST_MISMATCH`, or `STATUS_UNAVAILABLE`
- `checkedAt` and a visible `LIVE`, `MOCK`, or `REPLAY` source

The only valid allow tuple is `ALLOW + VERIFIED + RELEASE_VERIFIED`. Every other tuple fails closed, including malformed responses and timeouts.

## MCP stdio runtime

An MCP host starts `apps/gateway/src/index.mjs stdio`, not the artifact directly. The Gateway snapshots the artifact, computes its identity, and completes admission before spawning the server.

The admitted child uses newline-delimited JSON-RPC over stdin/stdout. The demo proves this sequence with the official MCP TypeScript client:

1. `initialize`
2. `notifications/initialized`
3. `tools/list`
4. `tools/call` for a manifest-declared tool

The runtime `tools/list` array must hash to the reviewed `toolSurfaceHash`. Unknown tool calls, surface drift, invalid JSON-RPC, duplicate list responses, and output limits fail closed. A blocked release exits before the child can answer `initialize`. stdout is reserved for MCP protocol messages; diagnostics use stderr.

## Idempotency and recovery

- Release operations use `register:<releaseId>`.
- Attestation operations use the signature digest.
- The Backend records `PENDING`, `SUBMITTED`, `COMPLETED`, or `FAILED` before and after chain interaction.
- Concurrent retries never send a second transaction.
- The reconciler checks receipts and canonical chain state before retrying or rebuilding projections.
- The indexer uses block/log identity deduplication, confirmations, checkpoints, and rewind for reorg recovery.
