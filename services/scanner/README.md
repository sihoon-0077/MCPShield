# MCPShield Security Scanner

## Master implementation additions

`scanRelease()` and ScanResult v1 remain compatible. `scanReleaseDetailed(options)`
adds `{ result, analysis, bundle }`. `analysis` includes tool/schema/annotation
changes, dependency and lifecycle diff, a CycloneDX 1.5 SBOM, review-only metadata
signals with source spans, and bounded synthetic probe descriptions.

```powershell
node services/scanner/src/cli.mjs --fixture demo/fixtures/mail-mcp-1.0.1 --baseline demo/fixtures/mail-mcp-1.0.0 --detailed true
node services/scanner/src/cli.mjs --npm is-number@7.0.0 --detailed true
node benchmarks/evaluate-metadata.mjs
```

Resolver `services/resolver/src/resolver.mjs` exports `resolveArtifact({source})`
where source is `{type:'local',path}`, `{type:'npm',spec}`, or
`{type:'tarball',url,integrity?}`. The compatibility input
`{sourceType,locator}` is also accepted. Returned `artifactDir` is an owned
temporary snapshot: copy it into your content-addressed store if needed, then
call `cleanup()`. Registry package scripts are never installed or executed.
Only HTTPS npm-registry sources are fetched; redirects and private/custom URLs
are rejected. Archive bytes have an independent SHA-256 and verified registry
integrity. Legacy artifactDigest retains its documented sorted path/NUL/bytes/NUL
tree algorithm. Tar extraction uses current node-tar in a new owned directory,
rejects links, traversal, duplicate/case-colliding names and Windows path aliases,
and caps downloaded/expanded bytes, file count and compression ratio.

Workers must call `scanResolvedArtifact({artifactDir,...options})`, which defaults
to static inspection and cannot yield PASSED without dynamic analysis. Explicit
`sandbox:'docker'` is the only dynamic route for ingested artifacts. Packages
without a declared MCP manifest remain `INCONCLUSIVE`; an empty tool list is
not a discovered surface. `scanSource({source,...options})` resolves, scans and
cleans up in one call. Network, integrity and archive failures throw typed-message
errors before admission; callers should record the failed job rather than retry
unsafe artifacts indefinitely.

Evidence `bundle.files` contains canonical JSON strings and `bundle.manifest`
has algorithm `sha256-path-merkle-v1`, root and inclusion proofs. Sorted paths
define leaves. `contentHash=SHA256(UTF8(content))`,
`leaf=SHA256(0x00 || UTF8(path) || 0x00 || contentHash)` and
`parent=SHA256(0x01 || left32 || right32)`; odd nodes duplicate themselves.
`verifyEvidenceBundle(bundle, expectedRoot)` checks all paths and proofs and
rebuilds the root; `verifyEvidenceLeaf` supports selective disclosure. The root
must come from a trusted attestation, not the supplied bundle itself. v1
`evidenceHash` still commits to findings; the full bundle root is a separate
`reportRoot` for the new backend. Source strings retain original Unicode bytes;
semantic normalization never silently rewrites artifact identity.

Each sandbox now creates eight unique synthetic credential/data canaries under
a disposable fake home. Reports contain hashes and event metadata only. Docker
adds a bounded noexec tmpfs. Linux isolation acceptance runs with:

```sh
MCPSHIELD_DOCKER_TESTS=1 node --test tests/security/docker-sandbox.test.mjs
```

This suite must run on Linux with Docker and node:22-alpine available; ordinary
Windows runs explicitly skip it. It checks read-only mounts/rootfs, dropped
capabilities, no-new-privileges, cgroup limits, outside-network denial, canary
exfiltration and timeout cleanup. Do not describe skipped checks as passed.
Optional OpenTelemetry spans correlate static/AI/sandbox/evidence stages with
the worker traceparent; source content is excluded from span attributes.

Current limits: no OCI image ingestion yet; SBOM is declared/lockfile based,
not a vulnerability database; probes are bounded deterministic templates, not
a measured LLM agent ASR benchmark. Metadata corpus is 16 synthetic author-labeled
cases and intentionally reports the implicit-scope false negative. Real agent
providers, independently labeled external datasets and kernel-level syscall
coverage remain separate validation work. Disable the additions by continuing
to use `scanRelease()` and the existing fixture CLI; existing hashes stay valid.

The scanner produces a canonical MCPShield `ScanResult` v1 from a controlled
fixture. It combines reproducible artifact/tool hashes, static rules, a
structured semantic analysis, and observed sandbox behavior. Raw canary data,
request bodies, process arguments, credentials, and file contents are never
included in results or observation logs.

## Quick start

Run from the repository root after `npm ci`:

```powershell
npm.cmd run scan:safe
npm.cmd run scan:malicious
npm.cmd run test:security
npm.cmd run benchmark:security
```

The reviewed fixture hashes are frozen in
`demo/fixtures/expected-hashes.json`. Tests fail if fixture content or the
canonical, order-independent tool surface changes without an explicit review.

## Analysis pipeline

1. Reject symlinks, path traversal, duplicate tool names, oversized artifacts,
   malformed release identifiers, and unsupported result sources.
2. Hash every artifact path and byte with SHA-256 and hash the canonicalized
   tool surface separately.
3. Run static rules for sensitive-file access and undeclared network egress.
4. Run the configured semantic analyzer. Timeout, invalid JSON, invalid finding
   shape, or HTTP failure automatically switches to the deterministic local
   structured fallback. Semantic findings remain `deterministic: false`, so an
   AI-only judgment cannot block a release.
5. Execute the fixture with a Node preload observer. It records sanitized
   `FS_READ`, `NETWORK`, and `CHILD_PROCESS` metadata. A token-protected local
   sink records only the SHA-256 hash and byte length of the dummy canary.
6. Validate the final result both with strict runtime guards and the canonical
   schemas under `packages/protocol/schemas`.

The default `local` mode is a child process intended for development. Use
`--sandbox docker` when the scanner runs directly on a host. Docker mode uses
an internal-only network, read-only mounts/filesystems, dropped capabilities,
`no-new-privileges`, and CPU/memory/PID limits. Timeout cleanup removes the
fixture, sink, network, and temporary canary state. When the scanner itself runs
inside a locked-down demo container, local mode stays within that container.

## Optional remote semantic analyzer

```powershell
$env:MCP_SHIELD_AI_URL='https://trusted-analyzer.example/v1/analyze'
$env:MCP_SHIELD_AI_TOKEN='<secret-manager-value>'
$env:MCP_SHIELD_ENABLE_REMOTE_AI='true'
node services/scanner/src/cli.mjs `
  --fixture demo/fixtures/mail-mcp-1.0.1 `
  --baseline demo/fixtures/mail-mcp-1.0.0 `
  --allow-remote-ai true `
  --ai-timeout-ms 2000
```

The request is `{ "prompt": "..." }`. The response must be
`{ "findings": [...] }`, and every finding must use
`SEMANTIC_BEHAVIOR_MISMATCH`, stage `AI`, and `deterministic: false`. Prompt
excerpts are size-limited and common private-key/token patterns are redacted.
No remote AI endpoint is needed for the demo. Merely setting an AI URL is not
enough to send source excerpts: remote analysis also requires the explicit
`--allow-remote-ai true` flag or `MCP_SHIELD_ENABLE_REMOTE_AI=true` opt-in.

Disable remote analysis by removing the opt-in (or unsetting the URL); the local
structured fallback remains active. This is the rollback path if the remote
analyzer is slow or unavailable.

## Submit a LIVE result to Backend

Register the release first with the same artifact and tool hashes. Then keep
the scanner credential in the environment rather than a command argument:

```powershell
$env:SCANNER_API_TOKEN='<16-or-more-character-random-secret>'
node services/scanner/src/cli.mjs `
  --fixture demo/fixtures/mail-mcp-1.0.1 `
  --baseline demo/fixtures/mail-mcp-1.0.0 `
  --submit-url http://127.0.0.1:3001/api/scans
```

The client validates the result before sending, uses
`Authorization: Bearer $SCANNER_API_TOKEN`, fails on redirects or non-2xx
responses, validates the Backend response, and permits plaintext HTTP only for
loopback development. The Backend stamps accepted results as `LIVE`.

## LIVE, REPLAY, and MOCK

- A normal scan defaults to `source: LIVE`.
- `--replay-file result.json` validates a saved result and stamps it
  `source: REPLAY`. Replay results are intentionally refused by the Backend
  submission client so they cannot be presented as live evidence.
- `MOCK` is part of the shared protocol for UI development; this scanner does
  not silently generate mock evidence.

```powershell
node services/scanner/src/cli.mjs --replay-file result.json
```

## Benchmark

```powershell
node benchmarks/evaluate.mjs --runs 10 --sandbox local
```

The report includes a confusion matrix, recall, precision, false-positive
rate, canary detection rate, and safe/malicious average, p50, p95, and maximum
latency. It exits non-zero unless recall and canary detection are 100% and the
safe-fixture blocking false-positive rate is 0%.

## Security boundaries and remaining limitations

- Fixtures are local demo artifacts only; never publish the malicious fixture.
- The preload observer is behavioral telemetry, not a tamper-proof kernel
  monitor. A hostile native binary could evade it. Deterministic static and
  canary evidence remain independent layers.
- Docker image availability is an operational dependency of host-level Docker
  mode. If Docker is unavailable or a sandbox times out without other blocking
  evidence, the result is `INCONCLUSIVE`, never a false pass.
- The sink binds to loopback by default. Its `/events` endpoint requires a
  per-run random bearer token and stores only canary hashes.
- No real personal data, production MCP package, external attack server, or
  committed secret is used.
