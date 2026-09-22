import assert from "node:assert/strict";
import test from "node:test";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scopedMailbox, scopedTools, scopedContractServer } from "./scoped-fixture.js";
import { scopedPreparedPolicy, preparedPolicy, policyVerdict } from "../../apps/api/src/control-policy.js";
import { checkedScopedSource } from "../../apps/validator/src/scoped-verification.js";
import { checkedValidatorPayload } from "../../apps/validator/src/v2.js";
import { comparePreparedScans } from "../../apps/validator/src/prepared-verification.js";
import { preparedTrust } from "../../apps/api/src/prepared-config.js";
import { hash, saveEvidence } from "../../apps/api/src/control-plane.js";
import { scopedPreparationContext } from "../../apps/api/src/scoped-config.js";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { attestationV2Domain, attestationV2Types, bytes32, exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";
// @ts-expect-error Shared exact source resolver.
import { resolveArtifact } from "../../services/resolver/src/resolver.mjs";
// @ts-expect-error Shared closure helper.
import { closureManifest } from "../../services/resolver/src/closure-files.mjs";
// @ts-expect-error Shared binding helpers.
import { createPreparedReleaseBinding, scopedPreparedExecutionPolicy } from "../../services/scanner/src/prepared-binding.mjs";
// @ts-expect-error Shared live HTTP scoped reviewer.
import { reviewScopedSemanticsV2 } from "../../services/scanner/src/scoped-semantic.mjs";
// @ts-expect-error Shared static source assessment.
import { inspectPreparedSources } from "../../services/scanner/src/prepared-review.mjs";
// @ts-expect-error Shared descriptor.
import { hashPreparedRuntimeDescriptor } from "../../services/resolver/src/runtime-descriptor.mjs";
// @ts-expect-error Shared evidence.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared surface.
import { toolSurfaceHash } from "../../services/scanner/src/tool-surface.mjs";
// @ts-expect-error Real collector argument commitment.
import { probeArgumentsDigest } from "../../services/scanner/src/mcp-probe.cjs";

const sha = (value: string | Buffer) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
const policy = scopedPreparedPolicy("LOCAL_CONTRACT_TEST"), policyHash = hash(policy), tenant = "scoped-validator-test", token = "synthetic-scoped-validator-operator";
async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-scoped-validator-")), root = join(directory, "source"); await mkdir(root);
  const provider = await scopedContractServer(), pkg = { name: "scoped-synthetic", version: "1.0.0", bin: "server.js", private: true };
  const files = { "package.json": JSON.stringify(pkg), "package-lock.json": JSON.stringify({ name: pkg.name, version: pkg.version, lockfileVersion: 3, packages: { "": pkg } }), "server.js": scopedMailbox() };
  for (const [path, bytes] of Object.entries(files)) await writeFile(join(root, path), bytes);
  const resolved = await resolveArtifact({ sourceType: "local", locator: root });
  const source = { ...exactReleaseIdentity(resolved), artifactDigest: resolved.artifactDigest, manifestDigest: resolved.manifestDigest, toolSurfaceHash: resolved.toolSurfaceHash };
  const sourceProvenance = { schemaVersion: "mcpshield.operator-code-artifact.v1", authority: "OPERATOR_LOCAL_CATALOG", contentClass: "CODE_ARTIFACT_NO_CUSTOMER_DATA", sourceArtifactDigest: source.artifactDigest };
  const provenancePath = join(directory, "validator-private.json"), sourcesPath = join(directory, "sources-private.json"), apiProvenancePath = join(directory, "api-private.json");
  const catalogue = { schemaVersion: "mcpshield.scoped-provenance-catalogue.v1", artifacts: [sourceProvenance] };
  for (const path of [provenancePath, apiProvenancePath]) await writeFile(path, JSON.stringify(catalogue));
  const sources = { schemaVersion: "mcpshield.validator-sources.v1", sources: [{ releaseId: source.releaseId, sourceType: "local", locator: root }] };
  await writeFile(sourcesPath, JSON.stringify(sources));
  const config = { builderImageDigest: sha("synthetic-builder"), platform: { os: "linux" as const, architecture: "amd64" as const } }, anchors = preparedTrust(config);
  const executionPolicy = scopedPreparedExecutionPolicy({ collectorDigest: anchors.collectorDigest, observerDigest: anchors.observerDigest, egressAllowHosts: ["mail-api.local", "exfil-sink.local"] }, policy.semantic);
  const contents = Object.entries(files).map(([path, content]) => ({ path, bytes: Buffer.from(content) }));
  // Actual HTTP reviews and source acquisition, but explicitly synthetic Docker observations/proofs.
  const closure = { ...closureManifest(contents.map(({ path, bytes }) => ({ path, type: "File", mode: 0o444, digest: sha(bytes) }))),
    contents, bytes: contents.reduce((total, file) => total + file.bytes.length, 0), source: "LIVE_DOCKER_IMAGE_EXPORT" };
  const review = inspectPreparedSources(closure), image = sha("SYNTHETIC_IMAGE_NOT_PRESENT");
  const semantic = await reviewScopedSemanticsV2({ files: review.files, tools: scopedTools, runtime: { profile: policy.profile, runtimeDigest: image, environmentDigest: closure.digest },
    executionPolicy, sourceProvenance, sourceArtifactDigest: source.artifactDigest, ai: provider.ai });
  assert.equal(semantic.scopeComplete, true, JSON.stringify(semantic.issues));
  const descriptor = { schemaVersion: "mcpshield.prepared-runtime.v1", stage: "CLOSURE_PREPARED", profile: "npm-closure-v1", sourceDigest: source.artifactDigest,
    sourceTreeDigest: source.artifactDigest, lockDigest: sha(files["package-lock.json"]), lockOrigin: "SUPPLIED", builderImageDigest: config.builderImageDigest, platform: config.platform,
    finalImageDigest: image, toolSurfaceHash: toolSurfaceHash(scopedTools), entrypoint: { path: "server.js", digest: sha(files["server.js"]) }, argv: ["/usr/local/bin/node", "/app/server.js"],
    policy: { acquisitionNetwork: "REGISTRY_ONLY_SEPARATE", installNetwork: "NONE", installScripts: "DISABLED", executionNetwork: "INTERNAL_SYNTHETIC_PROXY", user: "NON_ROOT", rootFilesystem: "READ_ONLY" } };
  const binding = createPreparedReleaseBinding({ sourceReleaseId: source.releaseId, descriptor, executionPolicy });
  const sourceDescriptorDigest = hashPreparedRuntimeDescriptor({ ...descriptor, stage: "PREFLIGHT", finalImageDigest: null, toolSurfaceHash: null });
  const validatorConfig = { provenancePath, sourcesPath, ai: provider.ai }, acquired = await checkedScopedSource(policy, binding, source, validatorConfig);
  const trusted = { ...anchors, finalImageDigest: image, platform: config.platform, closureDigest: closure.digest, entrypointDigest: descriptor.entrypoint.digest,
    sourceDescriptorDigest, sourceProvenance, sourceBudget: acquired.sourceBudget, scopedVerificationConfigHash: acquired.configHash };
  const step = (kind?: string) => ({ protocolComplete: true, timedOut: false, exitCode: 0, failureCode: null, pages: 1, permissionProfile: "NODE_PERMISSION_READ_ONLY_V1",
    runtimeIdentity: { imageDigest: image, platform: config.platform, argv: descriptor.argv }, toolSurfaceHash: binding.toolSurfaceHash, egressEvents: [], canaryExfiltration: false,
    callResults: semantic.reviews.probe.report.scenarios.filter((scenario: any) => scenario.kind === kind).map(({ toolCall }: any) => ({ name: toolCall.name,
      argumentsDigest: probeArgumentsDigest(toolCall.arguments), isError: false, contentHash: "b".repeat(64) })) });
  const result = { schemaVersion: "1.0.0", scanId: randomUUID(), releaseId: resolved.releaseId, artifactDigest: binding.artifactDigest, toolSurfaceHash: binding.toolSurfaceHash,
    scanStatus: "PASSED", findings: [], evidenceHash: `0x${"a".repeat(64)}`, source: "LIVE" };
  const docs: Record<string, any> = { "report.json": { ...result, scope: "RESTRICTED_NODE_DOCKER_V2" }, "prepared/binding.json": binding, "prepared/source-identity.json": source,
    "runtime/descriptor.json": descriptor, "runtime/execution-policy.json": executionPolicy, "runtime/tools.json": scopedTools,
    "prepared/observation.json": { source: "LIVE_DOCKER", identity: { observedDescriptorDigest: binding.descriptorDigest, sourceArtifactDigest: binding.sourceArtifactDigest,
      executionPolicyDigest: binding.executionPolicyDigest, finalImageDigest: image, preparationDescriptorDigest: hashPreparedRuntimeDescriptor({ ...descriptor, toolSurfaceHash: null }) },
      steps: { discovery: step(), normal: step("NORMAL"), adversarial: step("ADVERSARIAL") }, issues: [], scenarios: semantic.reviews.probe.report.scenarios,
      generation: { ...semantic.reviews.probe.execution, status: "SCOPED_GENERATED_VALIDATED" } },
    "static/closure-inventory.json": { ...review.inventory, source: closure.source }, "static/closure-report.json": { ...closureManifest(closure.entries), bytes: closure.bytes, sourceDescriptorDigest, installScripts: false, installNetwork: "NONE" },
    "static/closure-source.json": { complete: true, files: contents.map(({ path, bytes }) => ({ path, base64: bytes.toString("base64") })) },
    "static/findings.json": review.findings, "static/sbom.json": review.sbom, "semantic/reviews.json": semantic };
  const bundle = createEvidenceBundle(docs), identity = exactReleaseIdentity({ toolId: source.toolId, artifactDigest: binding.artifactDigest, manifestDigest: binding.manifestDigest, toolSurfaceHash: binding.toolSurfaceHash });
  const second = { ...result, scanId: randomUUID() }, independent = { result: second, bundle: createEvidenceBundle({ ...docs, "report.json": { ...second, scope: "RESTRICTED_NODE_DOCKER_V2" } }) };
  return { directory, root, files, source, sourceProvenance, catalogue, sources, apiProvenancePath, validatorConfig, acquired, config, binding, trusted, result, docs, bundle, identity, independent, provider,
    close: async () => { await provider.close(); await resolved.cleanup(); await rm(directory, { recursive: true, force: true }); } };
}

test("scoped validator requires its own freshly reacquired source and catalogue before provider or signing (actual local HTTP, synthetic Docker)", async () => {
  const f = await fixture();
  try {
    assert.equal(policyVerdict(f.bundle, f.result, policy, f.trusted), "PASS"); assert.equal(policyVerdict(f.bundle, f.result, preparedPolicy, f.trusted), "ABSTAIN");
    assert.equal(comparePreparedScans(f, f.independent, policy, f.trusted).semanticEvidenceMode, "LOCAL_CONTRACT_TEST");
    assert.ok(f.provider.counts.analyzer > 0 && f.provider.counts.critic > 0 && f.provider.counts.probe > 0);
    const calls = { ...f.provider.counts }, now = Math.floor(Date.now() / 1000), registry = `0x${"a".repeat(40)}`;
    const identity = { ...f.identity, exists: true, artifactDigest: bytes32(f.binding.artifactDigest), manifestDigest: bytes32(f.binding.manifestDigest), toolSurfaceDigest: f.binding.toolSurfaceHash };
    const scan = { scanId: f.result.scanId, releaseId: f.identity.releaseId, policyHash, status: "COMPLETED", result: { scanResult: f.result, reportRoot: f.bundle.manifest.root,
      validFrom: new Date(now * 1000).toISOString(), validUntil: new Date((now + 600) * 1000).toISOString() } };
    const template = { domain: attestationV2Domain(31337, registry), types: attestationV2Types, verdict: "PASS", payload: { releaseId: f.identity.releaseId, artifactDigest: identity.artifactDigest,
      manifestDigest: identity.manifestDigest, toolSurfaceDigest: identity.toolSurfaceDigest, policyHash, reportRoot: f.bundle.manifest.root, verdict: 0, validFrom: now, validUntil: now + 600,
      validatorSetVersion: 1, nonce: 0, deadline: now + 300 } };
    const context = { chainId: 31337, registryAddress: registry, policyHash, policy, scan, evidence: { bundle: f.bundle, reportRoot: f.bundle.manifest.root }, identity,
      validatorSetVersion: 1, nonce: 0, now, preparedRuntime: f.config, preparedRuntimeTrust: f.trusted, independentPreparedEvidence: f.independent, scopedPrepared: f.validatorConfig };
    assert.equal((await checkedValidatorPayload(template, context)).verdict, "PASS");
    await assert.rejects(checkedValidatorPayload(template, { ...context, scopedPrepared: undefined }), /CONFIG_REQUIRED/);
    await assert.rejects(checkedValidatorPayload(template, { ...context, independentPreparedEvidence: undefined }), /BINDING_MISMATCH/);
    await assert.rejects(checkedScopedSource(policy, { ...f.binding, descriptor: { ...f.binding.descriptor, sourceDigest: sha("different archive") } }, f.source, f.validatorConfig), /SOURCE_MISMATCH/);
    await assert.rejects(checkedScopedSource(policy, f.binding, { ...f.source, manifestDigest: sha("changed manifest") }, f.validatorConfig), /SOURCE_MISMATCH/);
    const lower = { ...policy, maxArtifactBytes: 1024 };
    assert.equal(policyVerdict(f.bundle, f.result, lower, f.trusted), "ABSTAIN");
    for (const budget of [undefined, { ...f.trusted.sourceBudget, sourceBytes: -1 }, { ...f.trusted.sourceBudget, sourceArtifactDigest: sha("other") }]) assert.equal(policyVerdict(f.bundle, f.result, policy, { ...f.trusted, sourceBudget: budget }), "ABSTAIN");
    await assert.rejects(checkedScopedSource(lower, f.binding, f.source, f.validatorConfig), /BUDGET_EXCEEDED/);
    const lowerHash = hash(lower);
    await assert.rejects(checkedValidatorPayload({ ...template, payload: { ...template.payload, policyHash: lowerHash } }, { ...context, policy: lower, policyHash: lowerHash, scan: { ...scan, policyHash: lowerHash } }), /BUDGET_EXCEEDED/);
    await writeFile(f.validatorConfig.provenancePath, JSON.stringify({ ...f.catalogue, artifacts: [] }));
    await assert.rejects(checkedValidatorPayload(template, context), /PROVENANCE_REQUIRED/);
    await writeFile(f.validatorConfig.provenancePath, JSON.stringify(f.catalogue));
    await writeFile(join(f.root, "server.js"), `${f.files["server.js"]}\n// changed source`);
    await assert.rejects(checkedValidatorPayload(template, context), /SOURCE_MISMATCH/);
    assert.deepEqual(f.provider.counts, calls, "failed authority/digest/budget gates never send review requests");
  } finally { await f.close(); }
});

test("scoped API template refreshes source budget/authority and cannot leak private context (actual SQL/HTTP evidence, synthetic Docker)", async () => {
  const f = await fixture(), store = await ControlStore.open(), registry = `0x${"b".repeat(40)}`;
  const options: any = { store, credentials: [{ tenantId: tenant, token, role: "operator" }], artifactPath: join(f.directory, "artifacts"), evidencePath: join(f.directory, "evidence"), evidenceKey: "1".repeat(64),
    preparedRuntime: f.config, scannerOptions: { sandbox: "docker", allowRemoteAi: false }, scopedPrepared: { provenancePaths: { [tenant]: f.apiProvenancePath }, ai: f.provider.ai },
    v2Relayer: { domain: attestationV2Domain(31337, registry), context: async () => ({ nonce: 0, validatorSetVersion: 1 }), close() {} } };
  const app = await buildApp({ adminApiToken: "synthetic-legacy-admin", scannerApiToken: "synthetic-legacy-scanner", controlPlane: options });
  try {
    const originalSource = { ...f.source, artifactDir: f.root, sourceType: "npm", legacyReleaseId: f.result.releaseId };
    await store.put(tenant, "release", f.source.releaseId, originalSource);
    const scoped = await scopedPreparationContext(options, tenant, policy, originalSource);
    await store.put(tenant, "release", f.identity.releaseId, { ...f.identity, artifactDigest: f.binding.artifactDigest, manifestDigest: f.binding.manifestDigest,
      toolSurfaceHash: f.binding.toolSurfaceHash, runtimeProfile: policy.profile, sourceReleaseId: f.source.releaseId });
    const request = { releaseId: f.identity.releaseId, policyHash, artifactDigest: f.binding.artifactDigest };
    const queued = await store.enqueue(tenant, request, "template", hash(request), randomUUID());
    const job = (await store.claim("worker"))!, now = Date.now(), key = await saveEvidence(options, tenant, f.bundle);
    await store.finish(job, "worker", { scanResult: f.result, reportRoot: f.bundle.manifest.root, evidenceKey: key,
      preparedRuntimeTrust: { ...f.trusted, scopedConfigHash: hash(scoped.frozen) }, validFrom: new Date(now - 1000).toISOString(), validUntil: new Date(now + 600000).toISOString(),
      analysis: { profile: policy.profile, verdict: "PASS", issues: [], ai: f.provider.ai, provenancePath: f.apiProvenancePath }, scopedPrepared: options.scopedPrepared });
    const read = () => app.inject({ url: `/v1/scans/${queued.scan.scanId}/attestation?validator=0x${"c".repeat(40)}`, headers: { authorization: `Bearer ${token}` } });
    const response = await read(); assert.equal(response.statusCode, 200, response.body); assert.equal(response.json().verdict, "PASS");
    const publicScan = await app.inject({ url: `/v1/scans/${queued.scan.scanId}`, headers: { authorization: `Bearer ${token}` } });
    assert.doesNotMatch(publicScan.body, /SYNTHETIC_NOT_A_PROVIDER_KEY|api-private|sourceBudget|sourceProvenance|scopedPrepared|scopedConfigHash|127\.0\.0\.1/);
    const lower = { ...policy, maxArtifactBytes: 1024 }, lowerHash = hash(lower);
    await store.put(tenant, "policy", lowerHash, { document: lower });
    await store.query("UPDATE cp_scans SET policy_hash=? WHERE scan_id=?", [lowerHash, job.scanId]);
    assert.equal((await read()).json().error.code, "SCOPED_SOURCE_BUDGET_EXCEEDED");
    await store.query("UPDATE cp_scans SET policy_hash=? WHERE scan_id=?", [policyHash, job.scanId]);
    await writeFile(f.apiProvenancePath, JSON.stringify({ ...f.catalogue, artifacts: [] }));
    assert.equal((await read()).json().error.code, "SCOPED_OPERATOR_PROVENANCE_REQUIRED");
  } finally { await app.close(); await f.close(); }
});
