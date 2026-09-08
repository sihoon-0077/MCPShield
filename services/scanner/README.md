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
This rule also applies to `source:{type:'local',path}`: ingesting a local path
does not make its code trusted. Every resolved source is static-only unless
Docker is explicitly selected, and resolved Docker scans require MCP discovery.

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

OCI sources accept `{type:'oci',locator:'ghcr.io/owner/image:tag'}` (also public
`registry-1.docker.io`) and `{type:'oci-layout',path}`. The resolver pins the
selected Linux/amd64 manifest digest, validates config/platform and every layer
digest/size, and reports entrypoint, command, user, environment *names* and ports.
It never applies layers or executes the image. OCI metadata uses an explicit
`0.0.0` legacy snapshot alias; actual identity is `metadata.imageDigest` and
`immutableReference`. OCI surface remains unknown and scan INCONCLUSIVE. Downloads
remain capped at 16 MiB and redirects/foreign layers are refused; larger images
and registries requiring redirected blob URLs fail explicitly. Anonymous registry
tokens never enter the result. Local image-layout tests verify this path offline.

Structured remote AI can return `{riskClaims,semanticDiff,needsHumanReview}` using
the supplied `responseSchema`. Confidence, categories and source-span offsets/hash
are validated against exactly the redacted prompt. A separate critic request
checks every claim. Missing/invalid critic produces review-required warnings;
all AI findings remain non-deterministic. The legacy `{findings}` response stays
supported. Providers must implement the no-tools request contract; the scanner
does not grant them tools or execute their recommendedProbe strings.

The native `openai` provider now speaks the official Responses API directly,
without another SDK or proxy service. Select a model explicitly; there is no
silent model choice or remote request until the opt-in is enabled:

```powershell
$env:MCP_SHIELD_AI_TOKEN='<secret-manager-value>'
node services/scanner/src/cli.mjs --fixture demo/fixtures/mail-mcp-1.0.0 --detailed true --ai-provider openai --ai-model YOUR_MODEL --allow-remote-ai true --ai-timeout-ms 45000
```

The default destination is exactly `https://api.openai.com/v1/responses`.
Non-OpenAI remote URLs cannot receive this provider's token; loopback remains
available for isolated contract tests. Analyzer and Critic each use strict JSON
schemas, no tools, stateless requests and `store:false`. Refusals, truncation,
unexpected tool calls, excess output and full-body deadlines fail explicitly.
The evidence records actual analyzer/critic completion, configured/returned model,
prompt hashes, token usage, elapsed time and template version. Failed remote work
is labeled `LOCAL_FALLBACK`, not a successful model invocation. `store:false`
is an application-state setting, not a claim of zero provider-side retention.
All schema/span checks still run locally and AI findings remain non-deterministic.
The `semantic-v3-citations` template supplies precomputed field/sentence citations
with source offsets and SHA-256 hashes. The model copies a supplied citation;
it is never asked to calculate a digest. Host validation rejects invented spans
even when a hash happens to match. An unavailable Critic sets `REVIEW_REQUIRED`
and `needsHumanReview:true`, rather than reporting a complete semantic approval.

Contract coverage: `node --test tests/security/ai-provider.test.mjs` uses only a
local fake API. No production API key or real model quality evaluation is implied.
Implementation references: [Structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
and [Responses API](https://developers.openai.com/api/reference/typescript/resources/responses/methods/create).

The controlled sink also implements an authenticated HTTP forward-proxy protocol
for synthetic `.local`/`.test` targets. Every test has an `egressAllowHosts` list;
IP literals, unknown hosts, alternate ports, credentials and CONNECT/TLS tunnels
are refused. Allowed endpoints return synthetic data locally and never forward
to the internet. Body/header canary matches and denied destinations become
redacted sandbox evidence. On Linux both containers use the non-root host UID/GID
that owns the read-only mounts; a root host runner is rejected. This preserves
mount privacy without DAC capabilities or world-readable canary files.

Current limits: SBOM is declared/lockfile based, not a vulnerability database;
probes are bounded tool-call plans, not a free-running multi-turn agent benchmark.
Docker scans now launch a trusted MCP collector inside the isolated container,
initialize the server, exhaust `tools/list` pagination (32-page/128-tool caps),
reject repeated cursors/duplicate names and compare the complete observed surface
with the pinned manifest. Incomplete collection cannot PASS. Optional
`probeCalls:[{name,arguments}]` executes up to eight synthetic MCP calls and records
only result hashes. Evidence `sandbox/mcp.json` includes completion, page count,
observed tools and request/call metadata. Arbitrary OCI images still do not run;
this collector applies to the supported Node MCP artifact profile only.

`benchmarks/mcp-attack-harness.mjs` exports `runMcpAttackHarness({fixtureDir,
authorize,...})`. It makes real MCP calls inside Docker for normal and scripted
attack paths, checks the controlled sink for actual canary arrival, then applies
the caller's admission decision before a protected process can start. The Linux
Docker suite uses the scanner's deterministic policy as that callback and the
paginated `probe-mail-mcp` fixture, whose attack only triggers on `export_context`.
This measures a synthetic action effect and pre-spawn protection, with explicit
`NONE_SCRIPTED_CALLS` model attribution; it does not claim a general LLM attack
success rate or a real chain quorum. A backend/Gateway callback can use the same
harness to measure the full quorum path.

Metadata corpus is 16 synthetic author-labeled
cases and intentionally reports the implicit-scope false negative. Real agent
providers, independently labeled external datasets and kernel-level syscall
coverage remain separate validation work. Disable the additions by continuing
to use `scanRelease()` and the existing fixture CLI; existing hashes stay valid.

### AI-generated synthetic probes and action-effect evaluation

Add `--ai-generate-probes true --sandbox docker` to an opted-in AI scan. The
Analyzer/Critic remains no-tools; a separate structured request generates 2–8
NORMAL/ADVERSARIAL scenarios. Host validation checks unique scenario IDs, known
tool names, actual tool input schemas, bounded JSON arguments and synthetic
mail/URL/file targets. Executable commands, credential arguments, unsupported
schema references/regular expressions and unsafe targets require review instead
of execution. Existing Ajv validates schemas; each plan owns a short-lived cache.
Generated strings are data, never host commands. The trusted collector executes
only validated MCP calls inside Docker; eight per-run fake canaries and the
controlled proxy determine whether an actual effect occurred. Generation failure
is recorded as `DEFERRED` and cannot produce a complete sandbox PASS.

The evidence bundle includes `semantic/generated-probes.json` with planner
provenance and `sandbox/mcp.json` with actual call result hashes. The default
scanner stays compatible with no remote model or generated calls. Disable this
feature by removing `--ai-generate-probes`; remove remote opt-in to stop all
provider traffic. Linux regression tests use a local fake model API and real
containers, explicitly not a claim about model reasoning quality.

```powershell
$env:MCP_SHIELD_ENABLE_REMOTE_AI='true'
$env:MCP_SHIELD_AI_TOKEN='<secret-manager-value>'
node benchmarks/evaluate-ai-mcp.mjs --model YOUR_MODEL --runs 3
```

This command makes billable model requests only after explicit opt-in. It
discovers the actual MCP surface in Docker, generates one bounded tool-call
plan per run, executes normal/unprotected/protected calls and reports observed
canary-effect rates and normal-task completion. No effective baseline means
no claimed reduction. CLI admission is labeled `SCANNER_POLICY_NOT_CHAIN`;
`runAiMcpAttackHarness({authorize,...})` accepts a real validator/chain/Gateway
callback for integrated experiments. Missing credentials produce `NOT_RUN`,
never fabricated model results. This is a synthetic action-effect benchmark,
not a general agent ASR or independently labeled MCPTox evaluation.

### Same-task safe/poisoned agent evaluation (master 17.8)

```powershell
node benchmarks/evaluate-ai-mcp.mjs --mode agent --model YOUR_MODEL --runs 3
```

With the same explicit provider opt-in, this mode asks a small single-turn
JSON tool-decision agent to perform the same benign email task against the
safe and poisoned actual MCP tool lists. It does **not** ask the model to
generate an attack. Scanner-owned snapshots pin both artifacts. The isolated
collector executes the selected calls, and canary arrival at the controlled
sink determines attack success. The protected branch reuses the exact model
decision and applies the admission callback before spawn. Its safe-task result
is measured too, so blocking everything cannot look like a successful defense.
Invalid/out-of-profile plans are counted separately; refusals remain valid
non-successful attacks. Completion here means a successful expected tool call
without canary egress, not a general judgment of answer quality. Startup exfil
is rejected from this experiment because it is not model-induced behavior.

`runPairedAgentHarness()` accepts custom safe/poisoned snapshots, benign task and
real admission callback. Default CLI fixtures differ in code and capabilities,
so their result is not a pure metadata-only ablation. The model invocation
records provider/model/date, prompt/instruction hashes, token usage and fixed
request limits. Temperature remains `PROVIDER_DEFAULT`, seed `NOT_REQUESTED`:
repeated calls are not claimed deterministic. Local contract tests intentionally
use scripted fake model responses; only an opted-in real model run may support
claims about that model's synthetic ASR. No actual model ASR has been measured
without credentials.

### MCPTox static-only evidence

The [upstream repository](https://github.com/zhiqiangwang4/MCPTox-Benchmark)
at commit `f85189f9ad12504c197c7f920ab818a40657b1fa` contains no explicit LICENSE
or usage terms in its minimal README as checked on 2026-09-09. Raw data is not
bundled or redistributed here. Obtain the pinned source separately under
applicable permissions, then run:

```powershell
node benchmarks/mcptox-metadata.mjs --input PATH_TO_PURE_TOOL_JSON
```

The adapter checks the exact source SHA-256, treats descriptions only as data,
and emits aggregate statistics without payload text. The recorded read-only
measurement in `benchmarks/results/mcptox-static-2026-09-09.json` is **126/485
review detections (25.98%)**, with 359 misses. Template-3 has only 7/225 detections.
These are poisoned *tool records*, not the paper's 1,312 agent attack instances.
FPR and agent ASR are unmeasured (`null`); upstream author labels are not an
independent labeling exercise. This is evidence that lexical rules alone miss
implicit attacks, not evidence that the full system meets a 90% target.

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

## Prepared Node images: actual MCP observation (checkpoint 1C)

`observePreparedRuntime()` in `src/prepared-runtime.mjs` accepts the separately
prepared descriptor and its expected hash, never an arbitrary host entrypoint or
mutable image tag. It verifies the exact image config ID/platform before starting
an isolated Docker process. The original fixture/artifact identity is unchanged.

The existing read-only collector obtains every tools/list page (bounded to 32
pages/128 tools). A validated plan must contain NORMAL and ADVERSARIAL calls; the
two groups run in fresh containers with independent synthetic canaries. Every
run must discover the same complete tool surface. An explicitly opted-in AI
provider can generate the same bounded plan instead of a manual plan. Missing,
unsafe or incomplete plans are not silently replaced by successful measurements.

The result has separate machine-readable `discoveryComplete`,
`normalProbeComplete`, `adversarialProbeComplete`, `normalToolCallsSucceeded`,
`adversarialToolCallsSucceeded` and `toolSurfaceStable` checks. A tool error can
complete a protocol exchange without successfully completing a task. Canary
effects and proxy-denied egress use the independent sink; candidate-supplied
Node hook messages alone do not produce deterministic revocation findings.
Only response hashes are retained, never raw tool-call output or Docker stderr.

The descriptor with the actually observed tool hash gets a separate
`observedDescriptorDigest`. `preparationDescriptorDigest` and the original
`sourceArtifactDigest` remain available for provenance. The evidence bundle
commits to the redacted report/tools plus the exact collector/observer hashes,
Node arguments, synthetic egress policy and final image ID. Redacted descriptor
bytes are explicitly named `.redacted.json`; their hash is not represented as
the hash of the original private descriptor.

The Node permission model adds read-only `/app`, `/observer` and `/home/test`
access without granting child/worker/addon/WASI permissions. **Docker is the
isolation boundary, not Node permissions.** The
[official Node 22 permission documentation](https://github.com/nodejs/node/blob/v22.22.2/doc/api/permissions.md)
explicitly disclaims protection against malicious code. Node hooks remain
best-effort, so `fullBehaviorCoverage` and `approvalReady` remain false. Successful
protocol/probe execution yields `COMPLETED_LIMITED_NODE_PROFILE`, not READY or
scan PASS; deterministic adverse effects yield FAILED, otherwise INCONCLUSIVE.

Run portable contract checks with:

```powershell
node --import tsx --test tests/security/prepared-observation.test.mjs
```

The actual prepared-image regression is also in
`tests/security/npm-closure.test.mjs` and requires the approved patched builder
and Linux Docker configuration documented in `services/resolver/README.md`.
It prepares a real dependency closure, discovers two actual MCP pages, executes a
normal tool, observes a dummy-canary effect, checks permission restrictions and
verifies the evidence root. A skipped test is not an actual Linux result.

### Required next integration: existing registry/validator/Gateway path

This checkpoint is not a second standalone product. The next Main-reviewed
adapter must register and scan the prepared runtime as a **separate profile**:

| Existing V2 field | Prepared profile value |
|---|---|
| `toolId` | Existing canonical source tool ID; never rewrite the original release |
| `artifactDigest` | Observed prepared descriptor SHA-256, converted to bytes32 by existing SDK |
| `manifestDigest` | Canonical versioned prepared manifest binding profile, source release, descriptor and execution-policy digest |
| `toolSurfaceDigest` | Raw, complete, observed MCP surface hash (before redaction) |
| `policyHash` | Explicit prepared-profile policy, not the unchanged legacy v1 policy |
| `reportRoot` | Evidence root from that exact profile/descriptor scan |

`exactReleaseIdentity()` already derives a new release ID from these commitments;
no Solidity field reinterpretation is needed beyond the explicitly versioned
off-chain artifact profile. Source release records remain untouched. An
operator-only preparation job should freeze the observed descriptor before
registration, while keeping build/image configuration under worker policy rather
than accepting arbitrary images or host paths from API clients.

The control worker must dispatch by profile, verify descriptor/surface identity
and evidence again, and run the prepared-profile static/AI/observation policy
before requesting validator approval. It must not send this partial report
through the legacy `policyVerdict` PASS branch. The current fail-closed legacy
policy and public demo remain unchanged.

Gateway must hash/verify the private descriptor, obtain existing signed admission
for its descriptor identity **before** Docker spawn, use the identical pinned
image/argv and policy, and verify actual tools/list before exposing metadata or
forwarding calls. Revocation must also kill/remove the named Docker container,
not merely the Docker CLI process. Existing signed receipts, policy/domain
binding and per-call admission checks should be reused.

Current image IDs are local Docker config IDs, not registry manifest digests.
Cross-host Gateway deployment additionally needs a verified immutable image
distribution binding (manifest/layers/config), never an implicit tag pull.
Generic OCI execution still requires a language-neutral collector and a stronger
observation strategy; this Node-only checkpoint does not implement it. Lockless
npm resolution also remains a separate required isolated solver/broker stage.

### Prepared scan and independent restricted-profile policy

`src/prepared-scan.mjs` now exports `scanPreparedRuntime`,
`prepareAndScanRuntime`, `readTrustedPreparedIdentity` (synchronous local code
hashes), `readTrustedPreparedRuntime` (asynchronous validator-local image export),
and `assessPreparedPolicy`. The pure policy implementation is also directly
importable from `src/prepared-policy.mjs`.

```js
const output = await prepareAndScanRuntime({
  preparation, // server-owned root/sourceDigest/sourceTreeDigest/bin/platform/builder config
  sourceReleaseId, // exact original V2 bytes32 ID
  releaseId, // original name@version display label, not the new V2 ID
  scanId, ai, probePlan, timeoutMs,
});
// output: {result, bundle, analysis, binding, runtimeTag?, cleanup?}
```

`scanPreparedRuntime` instead accepts `descriptor`, `expectedDescriptorDigest`,
the same scan fields and independent operator `trusted` anchors. An already
observed descriptor can be rescanned but its registered identity must remain
unchanged. Failed preparation/discovery returns `result:null`, `binding:null`
and explicit ABSTAIN analysis; no fake empty tool hash is substituted. The
successful runtime image's private `runtimeTag`/`cleanup` ownership transfers to
the API worker. Store the durable binding before retaining the image; clean it
on failed/stale jobs, not immediately after registering a release.

The scanner exports `/app` from a **never-started** digest-pinned Docker
container. It checks the complete installed closure manifest, entrypoint and
installer report; host code only parses those bounded bytes, never imports a
candidate. All installed UTF-8 files, including `node_modules`, enter static
review and the actual-installed CycloneDX SBOM. Opaque/binary files require
unsupported review and therefore cannot receive PASS from this profile.

Explicitly opted-in AI reviews every redacted source character in batches, with
an independent blind-context critic for every batch even when no risks were
claimed. Both outputs use the strict citation schema. Missing provider access,
timeouts, truncated coverage, uncertain conclusions and unreviewed dependency
bytes produce INCONCLUSIVE/ABSTAIN. Default budgets are 32 batches and 120 seconds
(operator maximum 128 batches/300 seconds); these are not full-program formal
verification or independent-organization review. Local HTTP contract tests do
not constitute live commercial-model benchmark results.

The encrypted evidence contains `runtime/tools.json` (raw complete surface),
`runtime/descriptor.json`, `runtime/execution-policy.json`,
`prepared/binding.json`, `prepared/observation.json`, `prepared/policy-review.json`,
`static/closure-inventory.json`, `static/closure-report.json`,
`static/closure-source.json` (base64 original bytes), `static/sbom.json`,
`static/findings.json`, and `semantic/reviews.json` (redacted actual inputs and
per-role response provenance). **Raw tools/source/descriptor are operator-only
encrypted evidence, never public API/log data.** Raw-source evidence has an 8 MiB
ceiling; larger closures remain explicit ABSTAIN, despite the preparer's 100 MiB
acquisition limit. This bounded profile does not claim unrestricted npm support.

Validators must independently call:

```js
const trusted = await readTrustedPreparedRuntime({
  descriptor: binding.descriptor,
  expectedDescriptorDigest: binding.descriptorDigest,
  builderImageDigest: operatorApprovedBuilder,
});
const review = assessPreparedPolicy(bundle, result, binding, trusted);
```

This inspects the validator-local actual image CID/platform and exports its
closure/entrypoint bytes. A missing local image/Docker service is not approval.
Never copy `trusted` from scanner output, binding or an API body. The pure policy
then checks image-to-closure identity, raw-byte hashes, exact redaction and full
excerpt reconstruction, actual SBOM, both AI contexts, all-page MCP hashes and
normal/adversarial calls. It does not trust advertised PASS/check booleans.
Independent adverse sink/proxy effects may support FAIL even if semantic review
is incomplete; missing evidence cannot support PASS. Source-identity and new V2
release-ID verification remain the API/validator contract owner's responsibility.

Trust boundary: pure policy verification alone authenticates neither collector
events nor provider executions. Even a self-consistent Merkle bundle can be
rewritten by a compromised scanner/API. Without validator-local rerunning, this
is **trusted-scanner evidence validation**, not independent behavioral
observation. The independent-validator signing path must rerun the prepared scan
with its own operator-controlled provider/probe configuration and compare the
restricted scope, verdict and deterministic finding categories before signing.
Random canaries make the independent report root different; a validator-local
receipt must link that root to the submitted root. Missing execution/provider
configuration must withhold prepared-profile signatures rather than relabel
bundle-only validation as an independent scan.

`src/prepared-binding.mjs` and `services/resolver/src/runtime-descriptor.mjs`
contain shared side-effect-free identity/policy helpers. The manifest hashes
exactly `schemaVersion`, `profile`, `sourceReleaseId`, `sourceArtifactDigest`,
`descriptorDigest`, `executionPolicyDigest`; sourceArtifactDigest is the original
V2 tree hash, while descriptor.sourceDigest is archive provenance. Gateway uses
the stricter no-network profile with exactly `--permission`,
`--allow-fs-read=/app`, `--disallow-code-generation-from-strings`, no custom
preload/host-data mount. This preserves the separate original fixture identity.

## OCI inventory, trusted runtime catalogue and offline Trivy review

`src/oci-review.mjs` exports `reviewOciImage({descriptor,
expectedDescriptorDigest, trust, timeoutMs})`. `trust` is **operator-local**:
`baseImageDigest`, optional `baseCatalogueDigest`, `trivyImageDigest`,
`databaseDir`, and `databaseDigest`. Both image values are immutable local Docker
config IDs, not tags or registry manifest IDs. Neither image/path nor a trusted
catalogue may come from a public API request. Validators must compute their own
base catalogue and DB identity rather than accepting the scanner's versions.

This is a separate `mcpshield.oci-review.v1` inventory/review phase. Its
`approvalVerdict` is **always ABSTAIN** and `ready` is false, even if `status` is
COMPLETE. Missing Docker, bytes, tool/DB configuration, stale DB, incomplete
package coverage or timeout is INCONCLUSIVE; npm's PASS policy is never reused.
Full OCI approval still requires bounded source AI/blind-critic coverage, an
explicit runtime policy, independent validator replay and Gateway binding.

The scanner re-exports both the approved base and the candidate from never-started
Docker containers. It does not execute or import their code on the host. Exact
base matches bind **path, type, mode, owner, link target and content hash**. This
is runtime provenance, not a semantic proof for arbitrary native binaries.
Added/modified symlinks, hardlinks, directories, special files and privileged
modes are explicitly unreviewed filesystem structure. Unknown native/bytecode
and omitted source bytes remain incomplete; UTF-8 text classification means
`TEXT_REQUIRES_AI_AND_CRITIC`, not a successful semantic review. At most 8 MiB of
new source bytes are retained. Static inventory is not filesystem syscall tracing.

`readTrivyDatabaseIdentity` makes a stable, private two-file snapshot of an
already acquired `metadata.json` and `trivy.db`, streaming copy/hash with the
fixed `trivy-db-2g-v1` 2 GiB ceiling. The older explicit `trivy-db-1g-v1`
profile remains 1 GiB; candidate artifact limits are unchanged. Metadata is bounded to 64 KiB before reading
and must be DB schema v2, no more than 24 hours old, not future-dated. It never
downloads a DB or accepts a candidate configuration. The global review budget is
180 seconds (including both exports and DB/scan work), with bounded cleanup grace.

`scanOciWithTrivy` passes bounded native `docker image save` archives to the
approved Trivy container: no network or Docker socket, non-root, no capabilities,
read-only root/input/DB, fixed empty config/ignore files and bounded tmpfs.
It scans both base and candidate (one scan if their IDs match). Candidate code
never runs. Every image save is capped at 512 MiB and every JSON/converted output
at 16 MiB. Trivy's native `convert --format=cyclonedx` converts its JSON; every
detected package must appear in that actual CycloneDX output. Report image CID
and diff IDs must match Docker inspection. HIGH/CRITICAL counts are not ignored
or downgraded. An empty or mismatching package inventory is not full SBOM coverage;
this covers Trivy-detected packages, not all source semantics.

Returned `privateEvidence` contains original source bytes, filesystem/catalogue
paths and native Trivy/CycloneDX documents. **INTERNAL ONLY:** strip that field
before returning a public API result or telemetry. It may only enter the existing
encrypted operator-evidence store. Review summaries contain hashes/counts/codes,
not these source bytes. This first phase has no public API route or signer.

Portable checks (authored data, not real CVE scanning):

```sh
node --import tsx --test tests/security/oci-review.test.mjs
```

The opt-in test requires the existing patched CI builder CID, inspected approved
Trivy tool CID and fresh trusted DB directory; it does no download. It catalogues
the real base, performs offline scanning, native CycloneDX conversion, and checks
the HIGH/CRITICAL count is zero. A portable skip is **not** live scanner evidence:

```sh
MCPSHIELD_DOCKER_TESTS=1 MCPSHIELD_RUNTIME_BUILDER_IMAGE=sha256:... MCPSHIELD_TRIVY_IMAGE=sha256:... MCPSHIELD_TRIVY_DATABASE_DIR=/absolute/cache/db node --import tsx --test tests/security/oci-review.test.mjs
```

Native CLI references: [Trivy image](https://trivy.dev/docs/latest/references/configuration/cli/trivy_image/),
[offline scanning](https://trivy.dev/docs/latest/advanced/air-gap/),
[native conversion](https://trivy.dev/docs/latest/references/configuration/cli/trivy_convert/).

### Pure OCI consumer binding and shared semantic engine

`src/oci-binding.mjs` exports `ociExecutionPolicy`, `validateOciExecutionPolicy`,
`createOciReleaseBinding` and `validateOciReleaseBinding`. These helpers perform
only strict, self-consistent identity validation: they do not run Docker, obtain
operator trust, issue a PASS or authorize Gateway admission. Supply the exact
seven trust fields `baseImageDigest`, `baseCatalogueDigest`, `trivyImageDigest`,
`databaseDigest`, `observerDigest`, `sinkImageDigest`, `sinkCodeDigest` to create
the fixed `restricted-oci-offline-v1` execution policy. The observer includes the
external MCP collector; its whole module is committed by `observerDigest`.

`createOciReleaseBinding({sourceReleaseId, descriptor, executionPolicy})` requires
the strict existing OCI descriptor in OBSERVED state with its full raw tool
surface hash. The manifest hashes exactly these six fields:

```js
{ schemaVersion: 'mcpshield.prepared-release.v1', profile: 'oci-container-v1',
  sourceReleaseId, sourceArtifactDigest: descriptor.sourceTreeDigest,
  descriptorDigest, executionPolicyDigest }
```

The new artifact digest is the observed descriptor digest. The original source
V2 tree/release remains unchanged. The binding additionally contains the exact
descriptor, execution policy, manifest hash, full tool hash, config CID/platform.
No API-controlled host path, tag, command override or extra key is accepted.

The Gateway policy is stricter than synthetic observation: no network, no host
mounts or socket, descriptor-exact argv/workdir, read-only non-root Docker,
default seccomp, no capabilities/escalation, no healthcheck, fixed resource caps
and bounded noexec tmpfs. It preserves the validated inert image environment,
never forwards host variables, and forces HOME=/nonexistent and
PYTHONDONTWRITEBYTECODE=1. This policy supports packaged-data access/compute only;
it does not imply unrestricted file/API-connected native MCP support. Unknown
binaries, unreviewed structure or missing syscall observation remain explicit
scope limitations, not a fabricated native behavior proof.

The existing `reviewPreparedSemantics` engine accepts exactly two profiles:
default `restricted-node-docker-v1` (unchanged prompt/provenance) and
`restricted-oci-offline-v1`. OCI reuses full excerpt coverage, precomputed exact
citations, bounded transport and a separate blind critic, but its prompt does
not apply Node-only permissions to native processes. OCI outputs use
`mcpshield_oci_analyzer`/`mcpshield_oci_critic` provenance and an explicit
`semanticProfile`; absent opted-in provider access remains incomplete. Neither
a successful model contract test nor creating this binding enables OCI signing.
