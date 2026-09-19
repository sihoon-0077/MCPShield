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

The shared V2 reader distinguishes `TRANSPORT_UNAVAILABLE` from `TRUST_REJECTED`.
Only positively observed transport failures of every configured RPC endpoint
qualify as an all-provider outage; each endpoint shares one total deadline.
Invalid identity, malformed RPC, partial negative decisions, stale/expired proofs,
reorganization and operator cancellation must not be converted to outage authority.

### OCI prepared identity (consumer contract; full execution integration pending)

`services/scanner/src/oci-binding.mjs` is the shared pure validator for profile
`oci-container-v1`; do not feed an OCI binding into the Node prepared validator.
An OBSERVED descriptor commits the original source tree, Docker config image ID,
platform, final filesystem, exact entrypoint/argv/environment and full tool surface.
Its hash becomes the derived `artifactDigest`. The derived `manifestDigest` hashes
exactly six canonical fields: `schemaVersion: mcpshield.prepared-release.v1`,
`profile: oci-container-v1`, `sourceReleaseId`, `sourceArtifactDigest`,
`descriptorDigest`, `executionPolicyDigest`. The original source release is immutable.
The derived Control ID still uses the same four-field Registry V2 ABI encoding above.

The fixed `restricted-oci-offline-v1` execution policy binds seven operator-local
anchors: `baseImageDigest`, `baseCatalogueDigest`, `trivyImageDigest`, `databaseDigest`,
`observerDigest`, `sinkImageDigest`, `sinkCodeDigest`. A caller-supplied matching hash
is not independent authority: the worker and each validator must acquire and check
their own trusted bytes. The fixed Gateway policy allows no network/host mounts and
does not grant arbitrary native binary or filesystem safety certification.
Inventory/Trivy phase `COMPLETE`, an OBSERVED descriptor and a valid binding are
**not PASS, READY or execution authorization**. Missing full semantic coverage,
independent replay or consumer enforcement remains an explicit incomplete requirement.

The next OCI versioned control policy explicitly binds
`semanticEvidenceMode: LOCAL_CONTRACT_TEST` to its policy hash. Its original-source
limit is `maxSourceBytes: 104857600`; `maxExpandedBytes` is a distinct bounded
expansion/export limit (at most 536870912), never an enlarged source allowance.
This is the approved in-progress cross-part contract, not evidence of completed
API/validator/Gateway integration. Analysis and summaries must preserve
`PROVIDER_QUALITY_NOT_MEASURED`; a local synthetic PASS is not a production model
quality endorsement. The privacy-scoped real-provider mode requires an explicit
new mode/version, not reinterpreting the local test policy.

Whole-source semantic review currently accepts only an explicit trusted
`disclosurePolicy: LOCAL_CONTRACT_TEST`, custom provider and numeric-loopback
endpoint for both analyzer and critic. `allowRemoteAi` alone grants no exception.
API callers cannot supply this setting. Raw source and environment stay in the
private encrypted evidence/local declared test boundary, never a remote provider.

### Scoped semantic v2 commitment (not an executable approval profile yet)

`restricted-node-docker-v2` and `restricted-oci-offline-v2` bind the exact
`scopedReviewPolicy()` object from `services/scanner/src/scoped-policy.mjs`.
It fixes disclosure limits, analyzer/critic/probe roles, risk-tier policy and
`LOCAL_CONTRACT_TEST|PROVIDER_EXECUTION` provenance. These modes hash differently;
the same runtime bytes therefore get a different manifest and Control release ID.
Runtime isolation is unchanged. The operator's exact-source catalogue declaration
must be checked independently; a package field or public API opt-in is not authority.

This is a commitment-only interface. Current v1 evidence assessors explicitly
return ABSTAIN for v2, including when every v1 evidence hash is recomputed to match
the new policy. End-to-end scoped caller/validator integration, provider execution
and provider quality measurement remain unfinished. Do not advertise these helpers
as externally reviewed or execution-ready releases.

#### Approved additive v2 integration work (not activated)

The prepared-Node slice preserves the existing `executionPolicy.semantic` member
and whole-object validation; it does not add a `scopedReview` alias or reinterpret
v1 evidence. Its explicit scanner exports are `buildScopedSemanticInputV2`,
`verifyScopedSemanticInputV2`, `reviewScopedSemanticsV2` and
`assessScopedPreparedPolicy`. Reuse v1 privacy/transport primitives where correct,
but do not change existing v1 behavior or enable a public API policy implicitly.

The full validated execution policy and independently obtained operator-local
exact-source provenance bind the selection. The local tier decision chooses one
bounded DTO; analyzer, blind critic and probe generator receive that same input
digest. Tier 3 additionally requires explicitly different analyzer2 model
configuration. Neither source text nor provider responses choose a lower tier.
Unknown classification/authority or disclosure-budget failure sends zero provider
requests. Raw source, runtime values and arbitrary customer data are not a fallback.
This is bounded disclosure under operator scope, not automatic privacy proof.

After closure verification and MCP discovery, run the scoped review once and
execute only its validated synthetic probe plan. The v2 evaluator reconstructs
source selection, provenance, policy/tier, prompt commitments and all required
role results, and matches planned scenarios to actual isolated observations.
Semantic review itself remains ABSTAIN. Only the aggregate evidence evaluator may
return restricted-profile PASS after static/SBOM/identity/dynamic checks; permanent
FAIL still needs bound deterministic evidence, not an AI-only warning.

API preparation, source catalogue reacquisition, independent validator verification,
Gateway exact profile/identity validation and OCI follow-through remain separate
required integration gates. A local HTTP contract server is labelled
LOCAL_CONTRACT_TEST, never actual provider-quality evidence. No private keys,
live customer data or paid provider requests are part of the integration tests.

The approved Node control policy is an additive `version: "2.0.0"` document with
`profile: "restricted-node-docker-v2"` and the exact `semantic: scopedReviewPolicy(mode)`
object. V1 policy bytes/hashes stay unchanged. `POST /v1/releases/:id/prepare` still
accepts only `{policyHash}`; clients cannot choose provider endpoints, credentials,
provenance or execution-policy bytes. Scanner entry points take the separate trusted
option `scopedReview: {executionPolicy, sourceProvenance}`; this call option is **not**
an alias in the committed execution policy. The assessor independently requires
operator-local `trusted.sourceProvenance`.

The local catalogue envelope is `mcpshield.scoped-provenance-catalogue.v1` with an
`artifacts` array of the existing exact four-field provenance declarations. The API
maps tenant IDs to local files; each validator uses its own file and existing
`ValidatorSources.v1` immutable-locator catalogue. Reopen bounded files at execution
and acceptance/signing boundaries; a missing, withdrawn or changed declaration
cannot reuse a stored approval. The provenance digest is the original source tree
digest (`source.artifactDigest`, `descriptor.sourceTreeDigest`,
`binding.sourceArtifactDigest`), **not** an archive digest or prepared descriptor hash.
Validators reacquire their own original source and compare the exact source identity
before reviewing their own runtime export. Existing PreparedConfig and source-identity
schemas do not gain private catalogue fields.

Public Node v2 summaries reuse only `semanticEvidenceMode` and fixed
`providerQuality: "PROVIDER_QUALITY_NOT_MEASURED"`, derived from the validated policy.
Paths, provider configuration, credentials and runtime trust objects stay private.
UI policy selection must match both v2 profile and evidence mode; absent/unknown
mode is not an inferred match. The collector's v2 probe evidence binds the exact
dispatched argument object by `argumentsDigest`, in addition to tool name/result
digest. Sharing a name does not establish that the generated scenario ran.

This slice does not activate OCI v2 or baseline support. Tier 3's distinct model
requirement must reflect actual transmitted model selectors; the current custom
transport has no such selector and cannot satisfy that requirement. Local Responses
contract tests do not become real-model quality evidence.

### Explicit local emergency execution

`mcpshield.break-glass-grant.v1` is separate from normal admission and FR407 receipts.
The operator-signed grant binds exact identities, tenant/policy/chain, actor/reason,
expiry (at most 60 seconds), one locally allowed read tool and canonical arguments.
Local configuration separately pins the client identity. Neither the grant nor its
encrypted usage audit changes normal `BLOCK`/`REVOKED` or removes revocation evidence.
Execution is separately labeled `BREAK_GLASS_OVERRIDE`; a locally constructed
`decisionSource: TRANSPORT_UNAVAILABLE` is unsigned outage evidence, not a chain proof.
Public HTTP rejects emergency options. Audit usage timestamps/normal decisions are
Gateway-recorded, not separately operator-signed; the ledger is local and unanchored.
See the Gateway README for exact private-file configuration and remaining limits.

### Composite readiness (additive contract)

The existing public `/health` remains the legacy liveness contract. The new
authenticated `GET /v1/health` is available to all three tenant roles and uses
`Cache-Control: no-store`. Its exact response shape is:

```json
{
  "schemaVersion": "mcpshield.health.v1",
  "status": "DEGRADED",
  "checkedAt": "2026-09-19T00:00:00.000Z",
  "components": {
    "api": {"status": "UP", "code": "API_READY", "checkedAt": "2026-09-19T00:00:00.000Z"},
    "database": {"status": "UP", "code": "DATABASE_READY", "checkedAt": "2026-09-19T00:00:00.000Z"},
    "chain": {"status": "NOT_CONFIGURED", "code": "CHAIN_NOT_CONFIGURED", "checkedAt": null},
    "scanner": {"status": "UNKNOWN", "code": "SCANNER_HEARTBEAT_MISSING", "checkedAt": null}
  }
}
```

Overall `READY`/HTTP 200 requires every component to be `UP`; otherwise
`DEGRADED`/HTTP 503. Component status is one of `UP`, `DOWN`, `UNKNOWN`,
`NOT_CONFIGURED`, `LIMITED`; codes are bounded fixed machine identifiers,
never arbitrary exception messages. Do not expose tenant IDs, RPC URLs,
credentials, paths, hostnames, worker IDs or raw daemon/provider output.

Checks must use an actual DB read, a bounded read-only chain probe and fresh
worker-reported scanner connectivity. Configuration alone or an empty queue
does not prove readiness. Static-only workers report LIMITED; missing/stale,
future or malformed observations do not become UP. Chain-only workers cannot
satisfy scanner readiness. Short caching (at most five seconds) and coalescing
bound probe load; component timestamps retain the original observation time.
The dashboard must treat a valid 503 report as degraded status independently
of normal inventory, hide stale success when a read fails, and never turn
readiness into release execution authorization. Auth errors remain ordinary
401/403; arbitrary 503 bodies are not trusted health reports.

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
