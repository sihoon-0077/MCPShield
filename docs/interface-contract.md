# MCPShield Interface Contracts

## Control API `/v1` and Registry V2

The original demo `/api` contract below is preserved; it is **not** the `/v1`
control-plane contract. Do not exchange their release IDs, signatures or status fields.

| Boundary | Release identity | Decision/status fields | Authority |
|---|---|---|---|
| Original `/api/admission/check` | `name@version` | `decision`, `releaseStatus` | Original demo ledger |
| Control `/v1/admission/check` | Exact `0x` bytes32 release ID | Display: `decision`, `status`; proof: `snapshot` + `signature` | Tenant-authenticated API; Gateway verifies the signed snapshot |
| Gateway result | Pinned Control release ID in signed mode | `decision`, `releaseStatus`, `decisionSource` | Verified API/organization proof, eligible signed cache, or configured direct RPC read |

The Control ID is `keccak256(abi.encode(toolId, artifactDigest, manifestDigest,
toolSurfaceDigest))`; all four encoded values are bytes32. Use
`packages/contracts-sdk/src/v2-identity.mjs`, not `keccak256(name@version)`.
Registry V2 attestations use `MCPShieldReleaseRegistry` / domain version `1`,
the configured chain and verifying contract, and the complete fields in
`packages/contracts-sdk/src/v2.ts`. This domain differs from the legacy registry below.

Control admission requires a tenant bearer credential and an exact release, artifact,
surface, policy, `strict|balanced` mode and operation class. The signed Ed25519
snapshot additionally binds tenant, chain, registry, validator-set version,
observed block/hash and validity. Gateway checks `snapshot.status`; it must not
treat an unsigned top-level `status` or `decision` as authorization.
An unavailable RPC produces an unsigned `BLOCK / UNVERIFIED / STATUS_UNAVAILABLE`;
it is an availability failure, **not** a signed REVOKED decision.

Gateway `decisionSource` is `API`, `CACHE`, `ORG_INDEXER` or `DIRECT_RPC`.
An explicitly configured organization issuer has its own key and credential.
Only network/timeout/5xx failures advance to cache, organization, then RPC;
4xx, malformed signatures and explicit denial never advance. Direct RPC is
read-only, bounded and not cached as an ALLOW proof. Its persistent local
revocation marker is unsigned negative state, not a portable chain certificate.
See `apps/gateway/README.md` for operator-only configuration and limits.

## Original demo `/api` contract

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

## MCP Streamable HTTP runtime

Remote clients connect to `POST /mcp`. The Gateway advertises the synthetic `list_messages` tool with `readOnlyHint: true`, invokes the exact local stdio release through the same admission boundary, and returns an MCP tool error if the release is not `VERIFIED`. The public demo uses no authentication and returns fake mail only; production data requires OAuth.

## Idempotency and recovery

- Release operations use `register:<releaseId>`.
- Attestation operations use the signature digest.
- The Backend records `PENDING`, `SUBMITTED`, `COMPLETED`, or `FAILED` before and after chain interaction.
- Concurrent retries never send a second transaction.
- The reconciler checks receipts and canonical chain state before retrying or rebuilding projections.
- The indexer uses block/log identity deduplication, confirmations, checkpoints, and rewind for reorg recovery.
