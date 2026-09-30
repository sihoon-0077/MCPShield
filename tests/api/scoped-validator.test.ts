import assert from "node:assert/strict";
import test from "node:test";
import { createHash, randomUUID, generateKeyPairSync } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scopedMailbox, scopedTools, scopedContractServer } from "./scoped-fixture.js";
import { scopedPreparedPolicy, scopedBaselinePreparedPolicy, preparedPolicy, policyVerdict, isScopedBaselinePolicy } from "../../apps/api/src/control-policy.js";
import { checkedScopedSource, refreshedScopedBaseline } from "../../apps/validator/src/scoped-verification.js";
import { checkedValidatorSources } from "../../apps/validator/src/source-verification.js";
import { checkedValidatorPayload } from "../../apps/validator/src/v2.js";
import { comparePreparedScans } from "../../apps/validator/src/prepared-verification.js";
import { preparedTrust } from "../../apps/api/src/prepared-config.js";
import { hash, saveEvidence } from "../../apps/api/src/control-plane.js";
import { scopedPreparationContext } from "../../apps/api/src/scoped-config.js";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { preparations } from "../../apps/api/src/preparation-store.js";
import { runPreparationWorkerOnce } from "../../apps/api/src/preparation-worker.js";
import { runControlWorkerOnce } from "../../apps/api/src/control-worker.js";
import { attestationV2Domain, attestationV2Types, bytes32, exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";
// @ts-expect-error Shared exact source resolver.
import { resolveArtifact } from "../../services/resolver/src/resolver.mjs";
// @ts-expect-error Shared closure helper.
import { closureManifest } from "../../services/resolver/src/closure-files.mjs";
// @ts-expect-error Shared binding helpers.
import { createPreparedReleaseBinding, scopedPreparedExecutionPolicy } from "../../services/scanner/src/prepared-binding.mjs";
// @ts-expect-error Shared live HTTP scoped reviewer.
import { reviewScopedSemanticsV2, reviewScopedSemanticsV21 } from "../../services/scanner/src/scoped-semantic.mjs";
// @ts-expect-error Shared comparison/closure checks; these test observations are synthetic, not Docker execution.
import { comparePreparedClosures, checkedPreparedBaselineEvidence } from "../../services/scanner/src/scoped-baseline.mjs";
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
// @ts-expect-error Existing synthetic Ed25519 source signature, no persisted private key.
import { signDemoPublisherManifest } from "../../services/resolver/src/demo-publisher.mjs";

const sha = (value: string | Buffer) => `sha256:${createHash("sha256").update(value).digest("hex")}`;
const policy = scopedPreparedPolicy("LOCAL_CONTRACT_TEST"), policyHash = hash(policy), tenant = "scoped-validator-test", token = "synthetic-scoped-validator-operator";
async function fixture(signed = false, version = "1.0.0", selectedPolicy = policy, before: any = null) {
  const policy = selectedPolicy, baselineMode = isScopedBaselinePolicy(policy);
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-scoped-validator-")), root = join(directory, "source");
  let provider: Awaited<ReturnType<typeof scopedContractServer>> | undefined, resolved: any;
  try {
  await mkdir(root); provider = await scopedContractServer();
  const pkg = { name: "scoped-synthetic", version, bin: "server.js", private: true };
  const files = { "package.json": JSON.stringify(pkg), "package-lock.json": JSON.stringify({ name: pkg.name, version: pkg.version, lockfileVersion: 3, packages: { "": pkg } }), "server.js": scopedMailbox() };
  for (const [path, bytes] of Object.entries(files)) await writeFile(join(root, path), bytes);
  resolved = await resolveArtifact({ sourceType: "local", locator: root });
  const source = { ...exactReleaseIdentity(resolved), artifactDigest: resolved.artifactDigest, manifestDigest: resolved.manifestDigest, toolSurfaceHash: resolved.toolSurfaceHash };
  const sourceProvenance = { schemaVersion: "mcpshield.operator-code-artifact.v1", authority: "OPERATOR_LOCAL_CATALOG", contentClass: "CODE_ARTIFACT_NO_CUSTOMER_DATA", sourceArtifactDigest: source.artifactDigest };
  const provenancePath = join(directory, "validator-private.json"), sourcesPath = join(directory, "sources-private.json"), apiProvenancePath = join(directory, "api-private.json");
  const catalogue: any = { schemaVersion: "mcpshield.scoped-provenance-catalogue.v1", artifacts: [sourceProvenance, ...(before ? [before.sourceProvenance] : [])] };
  if (signed) {
    const key = generateKeyPairSync("ed25519"), publisherId = "synthetic-test-publisher";
    catalogue.publishers = { ...(before?.catalogue.publishers ?? {}), [source.artifactDigest]: { publisherId, pinnedPublicKey: key.publicKey.export({ type: "spki", format: "pem" }).toString(),
      manifest: signDemoPublisherManifest({ publisherId, name: pkg.name, version: pkg.version, artifactDigest: source.artifactDigest }, key.privateKey) } };
  }
  for (const path of [provenancePath, apiProvenancePath]) await writeFile(path, JSON.stringify(catalogue));
  const sources: any = { schemaVersion: "mcpshield.validator-sources.v1", sources: [{ releaseId: source.releaseId, sourceType: "local", locator: root }, ...(before ? before.sources.sources : [])] };
  await writeFile(sourcesPath, JSON.stringify(sources));
  const config = { builderImageDigest: sha("synthetic-builder"), platform: { os: "linux" as const, architecture: "amd64" as const } }, anchors = preparedTrust(config);
  const executionPolicy = scopedPreparedExecutionPolicy({ collectorDigest: anchors.collectorDigest, observerDigest: anchors.observerDigest, egressAllowHosts: ["mail-api.local", "exfil-sink.local"] }, policy.semantic);
  const contents = Object.entries(files).map(([path, content]) => ({ path, bytes: Buffer.from(content) }));
  // Actual HTTP reviews and source acquisition, but explicitly synthetic Docker observations/proofs.
  const closure = { ...closureManifest(contents.map(({ path, bytes }) => ({ path, type: "File", mode: 0o444, digest: sha(bytes) }))),
    contents, bytes: contents.reduce((total, file) => total + file.bytes.length, 0), source: "LIVE_DOCKER_IMAGE_EXPORT" };
  const review = inspectPreparedSources(closure), image = sha("SYNTHETIC_IMAGE_NOT_PRESENT");
  const descriptor = { schemaVersion: "mcpshield.prepared-runtime.v1", stage: "CLOSURE_PREPARED", profile: "npm-closure-v1", sourceDigest: source.artifactDigest,
    sourceTreeDigest: source.artifactDigest, lockDigest: sha(files["package-lock.json"]), lockOrigin: "SUPPLIED", builderImageDigest: config.builderImageDigest, platform: config.platform,
    finalImageDigest: image, toolSurfaceHash: toolSurfaceHash(scopedTools), entrypoint: { path: "server.js", digest: sha(files["server.js"]) }, argv: ["/usr/local/bin/node", "/app/server.js"],
    policy: { acquisitionNetwork: "REGISTRY_ONLY_SEPARATE", installNetwork: "NONE", installScripts: "DISABLED", executionNetwork: "INTERNAL_SYNTHETIC_PROXY", user: "NON_ROOT", rootFilesystem: "READ_ONLY" } };
  const binding = createPreparedReleaseBinding({ sourceReleaseId: source.releaseId, descriptor, executionPolicy });
  const identity = exactReleaseIdentity({ toolId: source.toolId, artifactDigest: binding.artifactDigest, manifestDigest: binding.manifestDigest, toolSurfaceHash: binding.toolSurfaceHash });
  const baselineDocument = before ? { schemaVersion: "mcpshield.prepared-baseline-evidence.v1",
    selection: { releaseId: before.identity.releaseId, sourceIdentity: before.source, binding: before.binding, sourceProvenance: before.sourceProvenance },
    publisher: before.acquired.publisher ?? null, closure: { inventory: before.docs["static/closure-inventory.json"], report: before.docs["static/closure-report.json"],
      source: before.docs["static/closure-source.json"], sbom: before.docs["static/sbom.json"], findings: before.docs["static/findings.json"] },
    tools: scopedTools, discovery: before.docs["prepared/observation.json"].steps.discovery, observedAt: new Date().toISOString() } : null;
  if (baselineMode) { sources.baselines = { [identity.releaseId]: before?.identity.releaseId ?? null }; await writeFile(sourcesPath, JSON.stringify(sources)); }
  const sourceDescriptorDigest = hashPreparedRuntimeDescriptor({ ...descriptor, stage: "PREFLIGHT", finalImageDigest: null, toolSurfaceHash: null });
  const validatorConfig = { provenancePath, sourcesPath, ai: provider.ai }, acquired = await checkedScopedSource(policy, binding, source, validatorConfig, baselineDocument);
  const baselineTrust = baselineMode ? refreshedScopedBaseline(acquired, before?.trusted ?? null) : undefined;
  const comparison = baselineMode ? comparePreparedClosures({ current: closure, tools: scopedTools, executionPolicy,
    baseline: before ? { closure: before.closure, tools: scopedTools, executionPolicy: before.binding.executionPolicy } : null }) : undefined;
  const semantic = await (baselineMode ? reviewScopedSemanticsV21 : reviewScopedSemanticsV2)({ files: review.files, tools: scopedTools,
    runtime: { profile: policy.profile, runtimeDigest: image, environmentDigest: closure.digest }, executionPolicy, sourceProvenance, sourceArtifactDigest: source.artifactDigest, ai: provider.ai,
    ...(baselineMode ? { sourceIdentity: source, comparison, baseline: checkedPreparedBaselineEvidence(baselineDocument, acquired.scopedReview, baselineTrust)?.semanticInput ?? null } : {}) });
  assert.equal(semantic.scopeComplete, true, JSON.stringify(semantic.issues));
  const trusted = { ...anchors, finalImageDigest: image, platform: config.platform, closureDigest: closure.digest, entrypointDigest: descriptor.entrypoint.digest,
    sourceDescriptorDigest, sourceProvenance, sourceBudget: acquired.sourceBudget, scopedVerificationConfigHash: acquired.configHash, publisher: acquired.publisher,
    ...(baselineMode ? { sourceIdentity: source, baseline: baselineTrust } : {}) };
  const step = (kind?: string) => ({ protocolComplete: true, timedOut: false, exitCode: 0, failureCode: null, pages: 1, permissionProfile: "NODE_PERMISSION_READ_ONLY_V1",
    runtimeIdentity: { imageDigest: image, platform: config.platform, argv: descriptor.argv }, toolSurfaceHash: binding.toolSurfaceHash, egressEvents: [], canaryExfiltration: false,
    callResults: semantic.reviews.probe.report.scenarios.filter((scenario: any) => scenario.kind === kind).map(({ toolCall }: any) => ({ name: toolCall.name,
      argumentsDigest: probeArgumentsDigest(toolCall.arguments), isError: false, contentHash: "b".repeat(64) })) });
  const result = { schemaVersion: "1.0.0", scanId: randomUUID(), releaseId: resolved.releaseId, artifactDigest: binding.artifactDigest, toolSurfaceHash: binding.toolSurfaceHash,
    scanStatus: "PASSED", findings: [], evidenceHash: `0x${"a".repeat(64)}`, source: "LIVE" };
  const scope = baselineMode ? "RESTRICTED_NODE_DOCKER_V2_1" : "RESTRICTED_NODE_DOCKER_V2";
  const docs: Record<string, any> = { "report.json": { ...result, scope }, "prepared/binding.json": binding, "prepared/source-identity.json": source,
    ...(baselineMode ? { "prepared/baseline.json": baselineDocument, "static/package-diff.json": comparison } : {}),
    ...(acquired.publisher ? { "prepared/publisher.json": acquired.publisher } : {}),
    "runtime/descriptor.json": descriptor, "runtime/execution-policy.json": executionPolicy, "runtime/tools.json": scopedTools,
    "prepared/observation.json": { source: "LIVE_DOCKER", identity: { observedDescriptorDigest: binding.descriptorDigest, sourceArtifactDigest: binding.sourceArtifactDigest,
      executionPolicyDigest: binding.executionPolicyDigest, finalImageDigest: image, preparationDescriptorDigest: hashPreparedRuntimeDescriptor({ ...descriptor, toolSurfaceHash: null }) },
      steps: { discovery: step(), normal: step("NORMAL"), adversarial: step("ADVERSARIAL") }, issues: [], scenarios: semantic.reviews.probe.report.scenarios,
      generation: { ...semantic.reviews.probe.execution, status: "SCOPED_GENERATED_VALIDATED" } },
    "static/closure-inventory.json": { ...review.inventory, source: closure.source }, "static/closure-report.json": { ...closureManifest(closure.entries), bytes: closure.bytes, sourceDescriptorDigest, installScripts: false, installNetwork: "NONE" },
    "static/closure-source.json": { complete: true, files: contents.map(({ path, bytes }) => ({ path, base64: bytes.toString("base64") })) },
    "static/findings.json": review.findings, "static/sbom.json": review.sbom, "semantic/reviews.json": semantic };
  const bundle = createEvidenceBundle(docs);
  const second = { ...result, scanId: randomUUID() }, independent = { result: second, bundle: createEvidenceBundle({ ...docs, "report.json": { ...second, scope } }) };
  return { directory, root, files, source, sourceProvenance, catalogue, sources, apiProvenancePath, validatorConfig, acquired, config, binding, trusted, result, docs, bundle, identity, independent, provider, closure,
    close: async () => {
      const closed = await Promise.allSettled([provider!.close(), resolved.cleanup(), rm(directory, { recursive: true, force: true })]);
      const errors = closed.filter((result): result is PromiseRejectedResult => result.status === "rejected").map(result => result.reason);
      if (errors.length) throw new AggregateError(errors, "SCOPED_FIXTURE_CLEANUP_FAILED");
    } };
  } catch (error) {
    await Promise.allSettled([provider?.close(), resolved?.cleanup(), rm(directory, { recursive: true, force: true })]);
    throw error;
  }
}

test("scoped validator requires its own freshly reacquired source and catalogue before provider or signing (actual local HTTP, synthetic Docker)", async () => {
  for (const signed of [false, true]) {
  const f = await fixture(signed);
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
    if (signed) {
      assert.equal(f.acquired.publisher?.verification.behaviorSafety, "NOT_ASSESSED");
      for (const leaf of [undefined, {}, { ...f.acquired.publisher, verification: { ...f.acquired.publisher!.verification, publicKeyFingerprint: sha("other key") } }]) {
        const changed = { ...f.docs }; if (leaf === undefined) delete changed["prepared/publisher.json"]; else changed["prepared/publisher.json"] = leaf;
        const corrupted = { ...f, bundle: createEvidenceBundle(changed) };
        assert.throws(() => comparePreparedScans(corrupted, f.independent, policy, f.trusted), /PUBLISHER_EVIDENCE_MISMATCH/);
        const independent = { ...f.independent, bundle: createEvidenceBundle({ ...changed, "report.json": JSON.parse(f.independent.bundle.files["report.json"]) }) };
        assert.throws(() => comparePreparedScans(f, independent, policy, f.trusted), /PUBLISHER_EVIDENCE_MISMATCH/);
      }
      const unsigned = { ...f.catalogue }; delete unsigned.publishers;
      await writeFile(f.validatorConfig.provenancePath, JSON.stringify(unsigned));
      await assert.rejects(checkedValidatorPayload(template, context), /BINDING_MISMATCH/);
      const current = await checkedScopedSource(policy, f.binding, f.source, f.validatorConfig);
      assert.throws(() => comparePreparedScans(f, f.independent, policy, { ...f.trusted, publisher: current.publisher }), /PUBLISHER_EVIDENCE_MISMATCH/);
      await writeFile(f.validatorConfig.provenancePath, JSON.stringify(f.catalogue));
      const wrong = structuredClone(f.catalogue); wrong.publishers[f.source.artifactDigest].pinnedPublicKey = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
      await writeFile(f.validatorConfig.provenancePath, JSON.stringify(wrong));
      await assert.rejects(checkedValidatorPayload(template, context), /PUBLISHER_SIGNATURE_INVALID/);
      await writeFile(f.validatorConfig.provenancePath, JSON.stringify(f.catalogue));
    }
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
    await assert.rejects(checkedValidatorPayload(template, context), signed ? /PUBLISHER_SIGNATURE_INVALID/ : /SOURCE_MISMATCH/);
    assert.deepEqual(f.provider.counts, calls, "failed authority/digest/budget gates never send review requests");
  } finally { await f.close(); }
  }
});

test("scoped API template refreshes source budget/authority and cannot leak private context (actual SQL/HTTP evidence, synthetic Docker)", async () => {
  for (const signed of [false, true]) {
  const f = await fixture(signed), store = await ControlStore.open(), registry = `0x${"b".repeat(40)}`;
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
    if (signed) {
      const previous = (await store.scan(tenant, job.scanId))!.result!, docs = { ...f.docs };
      delete docs["prepared/publisher.json"];
      const unsigned = createEvidenceBundle(docs), unsignedKey = await saveEvidence(options, tenant, unsigned);
      await store.query("UPDATE cp_scans SET result_json=? WHERE scan_id=?", [JSON.stringify({ ...previous, evidenceKey: unsignedKey, reportRoot: unsigned.manifest.root }), job.scanId]);
      assert.equal((await read()).json().error.code, "SCOPED_PUBLISHER_EVIDENCE_MISMATCH");
      await store.query("UPDATE cp_scans SET result_json=? WHERE scan_id=?", [JSON.stringify(previous), job.scanId]);
    }
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
  }
});

test("2.1 validator pins explicit null/prepared ID in its own source file and refreshes both authorities before signing (synthetic Docker)", async () => {
  const policy = scopedBaselinePreparedPolicy("LOCAL_CONTRACT_TEST"), policyHash = hash(policy), before = await fixture(true);
  try {
    for (const baseline of [null, before]) {
      const f = await fixture(true, "1.0.1", policy, baseline);
      try {
        assert.equal(policyVerdict(f.bundle, f.result, policy, f.trusted), "PASS");
        assert.equal(policyVerdict(f.bundle, f.result, scopedPreparedPolicy("LOCAL_CONTRACT_TEST"), f.trusted), "ABSTAIN");
        assert.equal(comparePreparedScans(f, f.independent, policy, f.trusted).verdict, "PASS");
        assert.equal(f.sources.sources.some((row: any) => row.releaseId === f.identity.releaseId), false, "source catalogue contains source IDs, not prepared IDs");
        const calls = { ...f.provider.counts }, now = Math.floor(Date.now() / 1000), registry = `0x${"d".repeat(40)}`;
        const identity = { ...f.identity, exists: true, artifactDigest: bytes32(f.binding.artifactDigest), manifestDigest: bytes32(f.binding.manifestDigest), toolSurfaceDigest: f.binding.toolSurfaceHash };
        const scan = { scanId: f.result.scanId, releaseId: f.identity.releaseId, baselineReleaseId: baseline?.identity.releaseId ?? null, policyHash, status: "COMPLETED", result: { scanResult: f.result,
          reportRoot: f.bundle.manifest.root, validFrom: new Date(now * 1000).toISOString(), validUntil: new Date((now + 600) * 1000).toISOString() } };
        const template = { domain: attestationV2Domain(31337, registry), types: attestationV2Types, verdict: "PASS", payload: { releaseId: f.identity.releaseId,
          artifactDigest: identity.artifactDigest, manifestDigest: identity.manifestDigest, toolSurfaceDigest: identity.toolSurfaceDigest, policyHash, reportRoot: f.bundle.manifest.root,
          verdict: 0, validFrom: now, validUntil: now + 600, validatorSetVersion: 1, nonce: 0, deadline: now + 300 } };
        const context = { chainId: 31337, registryAddress: registry, policyHash, policy, scan, evidence: { bundle: f.bundle, reportRoot: f.bundle.manifest.root }, identity,
          validatorSetVersion: 1, nonce: 0, now, preparedRuntime: f.config, preparedRuntimeTrust: f.trusted, independentPreparedEvidence: f.independent, scopedPrepared: f.validatorConfig };
        assert.equal((await checkedValidatorPayload(template, context)).verdict, "PASS");
        for (const selected of [undefined, {}, { [f.identity.releaseId]: baseline ? null : before.identity.releaseId }, { [f.source.releaseId]: baseline?.identity.releaseId ?? null }]) {
          const changed = structuredClone(f.sources); if (selected === undefined) delete changed.baselines; else changed.baselines = selected;
          await writeFile(f.validatorConfig.sourcesPath, JSON.stringify(changed));
          await assert.rejects(checkedValidatorPayload(template, context), /SCOPED_VALIDATOR_BASELINE_(?:REQUIRED|MISMATCH)/);
        }
        await writeFile(f.validatorConfig.sourcesPath, JSON.stringify(f.sources));
        for (const map of [null, [], { [f.identity.releaseId]: undefined }, { [f.identity.releaseId.toUpperCase()]: null }, { [f.identity.releaseId]: "bad" },
          Object.fromEntries(Array.from({ length: 129 }, (_, i) => [`0x${i.toString(16).padStart(64, "0")}`, null]))]) {
          assert.throws(() => checkedValidatorSources({ ...f.sources, baselines: map }), /BASELINES_INVALID/);
        }
        const omitted = { ...scan }; delete (omitted as any).baselineReleaseId;
        await assert.rejects(checkedValidatorPayload(template, { ...context, scan: omitted }), /BINDING_MISMATCH/);
        for (const leaf of [undefined, baseline ? { ...f.docs["prepared/baseline.json"], publisher: null } : {}]) {
          const docs = { ...f.docs }; if (leaf === undefined) delete docs["prepared/baseline.json"]; else docs["prepared/baseline.json"] = leaf;
          assert.throws(() => comparePreparedScans({ ...f, bundle: createEvidenceBundle(docs) }, f.independent, policy, f.trusted), /DID_NOT_CONFIRM/);
        }
        if (baseline) {
          const removed = structuredClone(f.catalogue); delete removed.publishers[before.source.artifactDigest];
          await writeFile(f.validatorConfig.provenancePath, JSON.stringify(removed));
          await assert.rejects(checkedValidatorPayload(template, context), /PUBLISHER_SIGNATURE_REQUIRED/);
          const rotated = structuredClone(f.catalogue), key = generateKeyPairSync("ed25519"), entry = rotated.publishers[before.source.artifactDigest];
          entry.pinnedPublicKey = key.publicKey.export({ type: "spki", format: "pem" }).toString();
          const { publisherId, name, version, artifactDigest } = entry.manifest.payload;
          entry.manifest = signDemoPublisherManifest({ publisherId, name, version, artifactDigest }, key.privateKey);
          await writeFile(f.validatorConfig.provenancePath, JSON.stringify(rotated));
          await assert.rejects(checkedValidatorPayload(template, context), /BINDING_MISMATCH/);
          await writeFile(f.validatorConfig.provenancePath, JSON.stringify(f.catalogue));
          const rebinding = structuredClone(f.docs["prepared/baseline.json"]);
          rebinding.selection.binding = createPreparedReleaseBinding({ sourceReleaseId: before.source.releaseId, descriptor: before.binding.descriptor,
            executionPolicy: { ...before.binding.executionPolicy, egressAllowHosts: ["other.local"] } });
          rebinding.selection.releaseId = exactReleaseIdentity({ toolId: before.source.toolId, ...rebinding.selection.binding }).releaseId;
          await assert.rejects(checkedScopedSource(policy, f.binding, f.source, f.validatorConfig, rebinding), /BASELINE_MISMATCH/);
          await writeFile(join(before.root, "server.js"), before.files["server.js"] + "\n// changed baseline");
          await assert.rejects(checkedValidatorPayload(template, context), /PUBLISHER_SIGNATURE_INVALID/);
          await writeFile(join(before.root, "server.js"), before.files["server.js"]);
        }
        assert.deepEqual(f.provider.counts, calls, "failed independent authority never issues provider requests; no signer/POST is called in this boundary test");
      } finally { await f.close(); }
    }
  } finally { await before.close(); }
});

for (const driver of ["SQLITE", "POSTGRESQL"]) test(`2.1 prepare/rescan freezes selected baseline, isolates null cache, preserves original ownership and refreshes before template (real ${driver}, synthetic Docker)`,
  { skip: driver === "POSTGRESQL" && !process.env.MCPSHIELD_POSTGRES_TEST_URL }, async t => {
  const tenant = `baseline-${randomUUID()}`;
  const resources: (() => Promise<void>)[] = [];
  t.after(async () => {
    const errors = []; for (const close of resources.reverse()) try { await close(); } catch (error) { errors.push(error); }
    if (errors.length) throw new AggregateError(errors, "BASELINE_TEST_CLEANUP_FAILED");
  });
  let location = ":memory:";
  if (driver === "POSTGRESQL") {
    const { Pool } = await import("pg"), pool = new Pool({ connectionString: process.env.MCPSHIELD_POSTGRES_TEST_URL });
    // Isolate global queue claimers from other concurrent CI tests in our newly owned schema.
    const schema = `baseline_${randomUUID().replaceAll("-", "")}`;
    assert.match(schema, /^baseline_[a-f0-9]{32}$/);
    let created = false;
    resources.push(async () => { try { if (created) await pool.query(`DROP SCHEMA "${schema}" CASCADE`); } finally { await pool.end(); } });
    await pool.query(`CREATE SCHEMA "${schema}"`); created = true;
    const target = new URL(process.env.MCPSHIELD_POSTGRES_TEST_URL!); target.searchParams.set("options", `-csearch_path=${schema}`); location = target.toString();
  }
  const policy = scopedBaselinePreparedPolicy("LOCAL_CONTRACT_TEST"), policyHash = hash(policy), before = await fixture(); resources.push(before.close);
  const initial = await fixture(false, "1.0.1", policy); resources.push(initial.close);
  const current = await fixture(false, "1.0.1", policy, before); resources.push(current.close);
  const store = await ControlStore.open(location);
  let app!: Awaited<ReturnType<typeof buildApp>>;
  resources.push(async () => { if (app) await app.close(); else await store.close(); });
  assert.equal(store.driver, driver);
  const registry = `0x${"e".repeat(40)}`, cleanups: string[] = [], inspections: string[] = [];
  let executed = 0, duringScan: (() => Promise<void>) | undefined;
  const options: any = { store, credentials: [{ tenantId: tenant, token, role: "operator" }], artifactPath: join(current.directory, "artifacts"), evidencePath: join(current.directory, "evidence"), evidenceKey: "1".repeat(64),
    preparedRuntime: current.config, scannerOptions: { sandbox: "docker", allowRemoteAi: false }, scopedPrepared: { provenancePaths: { [tenant]: current.apiProvenancePath }, ai: current.provider.ai },
    inspectPreparedRuntime: async ({ descriptor }: any) => {
      inspections.push(descriptor.sourceTreeDigest);
      const selected = descriptor.sourceTreeDigest === before.source.artifactDigest ? before : current;
      return Object.fromEntries(["builderImageDigest", "collectorDigest", "observerDigest", "finalImageDigest", "platform", "closureDigest", "sourceDescriptorDigest", "entrypointDigest"].map(key => [key, (selected.trusted as any)[key]]));
    },
    v2Relayer: { domain: attestationV2Domain(31337, registry), context: async () => ({ nonce: 0, validatorSetVersion: 1 }), close() {} } };
  const output = async (input: any) => {
    executed++; const selected = input.scopedReview.baseline === null ? initial : current;
    assert.equal(input.trusted.baseline?.releaseId ?? null, input.scopedReview.baseline?.releaseId ?? null);
    assert.deepEqual(input.trusted.sourceIdentity, selected.source);
    const result = { ...selected.result, scanId: input.scanId }, docs = { ...selected.docs, "report.json": { ...selected.docs["report.json"], ...result } }, tag = `mcpshield-runtime-${randomUUID()}:local`;
    await duringScan?.();
    return { binding: selected.binding, result, bundle: createEvidenceBundle(docs), analysis: { verdict: "PASS", issues: [] }, runtimeTag: tag, cleanup: async () => { cleanups.push(tag); } };
  };
  options.prepareRuntime = output; options.scanPreparedRuntime = output;
  app = await buildApp({ adminApiToken: "synthetic-legacy-admin", scannerApiToken: "synthetic-legacy-scanner", controlPlane: options });
  const headers = { authorization: `Bearer ${token}` }, request = (key: string, selection: any) => app.inject({ method: "POST", url: `/v1/releases/${current.source.releaseId}/prepare`,
    headers: { ...headers, "idempotency-key": key }, payload: { policyHash, ...selection } });
  const rescan = (key: string, selection: any) => app.inject({ method: "POST", url: "/v1/scans", headers: { ...headers, "idempotency-key": key },
    payload: { releaseId: current.identity.releaseId, policyHash, ...selection } });
    await store.put(tenant, "policy", policyHash, { policyHash, document: policy });
    for (const f of [before, current]) await store.put(tenant, "release", f.source.releaseId, { ...f.source, artifactDir: f.root, sourceType: "npm", legacyReleaseId: f.result.releaseId });
    const source = (await store.get(tenant, "release", current.source.releaseId))!;
    const oldRequest = { releaseId: before.identity.releaseId, artifactDigest: before.binding.artifactDigest, policyHash: hash(scopedPreparedPolicy("LOCAL_CONTRACT_TEST")) };
    const old = await store.enqueue(tenant, oldRequest, "baseline-seed", hash(oldRequest), randomUUID()), job = (await store.claim("seed"))!;
    const result = { ...before.result, scanId: old.scan.scanId }, bundle = createEvidenceBundle({ ...before.docs, "report.json": { ...before.docs["report.json"], ...result } });
    const evidenceKey = await saveEvidence(options, tenant, bundle);
    await store.finish(job, "seed", { scanResult: result, evidenceKey, reportRoot: bundle.manifest.root, preparedRuntimeTrust: before.trusted });
    await store.put(tenant, "release", before.identity.releaseId, { ...before.identity, artifactDigest: before.binding.artifactDigest, manifestDigest: before.binding.manifestDigest,
      toolSurfaceHash: before.binding.toolSurfaceHash, runtimeProfile: policy.profile, sourceReleaseId: before.source.releaseId, semanticEvidenceMode: "LOCAL_CONTRACT_TEST",
      preparedEvidenceKey: evidenceKey, preparedReportRoot: bundle.manifest.root, runtimeTag: "owned-baseline", status: "REVOKED" });
    const incompatible = await app.inject({ method: "POST", url: "/v1/scans", headers: { ...headers, "idempotency-key": "old-runtime-new-policy" },
      payload: { releaseId: before.identity.releaseId, policyHash, baselineReleaseId: null } });
    assert.equal(incompatible.statusCode, 409); assert.equal(incompatible.json().error.code, "SCOPED_EXECUTION_POLICY_MISMATCH");
    assert.equal((await store.scanUsage(tenant)).queued, 0);
    for (const selection of [{}, { baselineReleaseId: false }, { baselineReleaseId: "bad" }, { baselineReleaseId: "0X" + "a".repeat(64) }]) assert.equal((await request(randomUUID(), selection)).statusCode, 400);
    const nullRequest = await request("initial", { baselineReleaseId: null }); assert.equal(nullRequest.statusCode, 202, nullRequest.body);
    assert.equal(nullRequest.json().preparation.baselineReleaseId, null);
    await runPreparationWorkerOnce(store, options);
    const first = (await preparations(store, tenant, nullRequest.json().preparation.preparationId))[0];
    assert.equal(first.status, "COMPLETED", JSON.stringify(first.lastError)); assert.equal(first.result?.verdict, "PASS");
    const owned = (await store.get(tenant, "release", current.identity.releaseId))!, initialScan = (await store.scan(tenant, first.result!.scanId))!;
    const downgrade = await app.inject({ method: "POST", url: "/v1/scans", headers: { ...headers, "idempotency-key": "new-runtime-old-policy" },
      payload: { releaseId: current.identity.releaseId, policyHash: hash(scopedPreparedPolicy("LOCAL_CONTRACT_TEST")) } });
    assert.equal(downgrade.statusCode, 409); assert.equal(downgrade.json().error.code, "SCOPED_EXECUTION_POLICY_MISMATCH");
    const appeal = (await app.inject({ method: "POST", url: `/v1/releases/${current.identity.releaseId}/appeals`, headers,
      payload: { reason: "Synthetic incompatible current policy" } })).json().appeal;
    const appealed = await app.inject({ method: "POST", url: "/v1/scans", headers: { ...headers, "idempotency-key": "incompatible-appeal" },
      payload: { releaseId: current.identity.releaseId, policyHash: hash(scopedPreparedPolicy("LOCAL_CONTRACT_TEST")), appealId: appeal.appealId } });
    assert.equal(appealed.statusCode, 409); assert.equal(appealed.json().error.code, "SCOPED_EXECUTION_POLICY_MISMATCH");
    assert.equal((await store.get(tenant, "appeal", appeal.appealId))?.rescan, null);
    assert.equal(initialScan.request.baselineReleaseId, null); assert.equal(initialScan.result?.preparedRuntimeTrust.baseline, null);
    assert.equal((await request("initial", { baselineReleaseId: before.identity.releaseId })).statusCode, 409);
    const idRequest = await request("baseline", { baselineReleaseId: before.identity.releaseId }); assert.equal(idRequest.statusCode, 202, idRequest.body);
    await runPreparationWorkerOnce(store, options);
    const second = (await preparations(store, tenant, idRequest.json().preparation.preparationId))[0];
    assert.equal(second.status, "COMPLETED", JSON.stringify(second.lastError)); assert.equal(second.result?.verdict, "PASS");
    const selectedScan = (await store.scan(tenant, second.result!.scanId))!;
    assert.equal(selectedScan.request.baselineReleaseId, before.identity.releaseId);
    assert.equal(selectedScan.result?.preparedRuntimeTrust.baseline.releaseId, before.identity.releaseId);
    assert.notEqual(selectedScan.result?.reportRoot, initialScan.result?.reportRoot);
    assert.deepEqual(await store.get(tenant, "release", current.identity.releaseId), owned, "old runtime tag, proof and chain projection are never overwritten");
    assert.equal(cleanups.length, 1); assert.notEqual(cleanups[0], owned.runtimeTag);
    assert.equal((await rescan("null-hit", { baselineReleaseId: null })).json().scan.scanId, initialScan.scanId);
    assert.equal((await rescan("id-hit", { baselineReleaseId: before.identity.releaseId })).json().scan.scanId, selectedScan.scanId);
    assert.equal((await rescan("null-hit", { baselineReleaseId: before.identity.releaseId })).statusCode, 409);
    assert.equal((await rescan("missing", {})).statusCode, 400);
    // Deliberately remove the new field from a stored old row: JSON missing is not explicit null.
    const damaged = { ...initialScan.request }; delete damaged.baselineReleaseId;
    await store.query("UPDATE cp_scans SET request_json=? WHERE scan_id=?", [JSON.stringify(damaged), initialScan.scanId]);
    const miss = await rescan("null-not-missing", { baselineReleaseId: null }); assert.equal(miss.json().reusedResult, false, miss.body);
    await runControlWorkerOnce(store, options);
    assert.equal((await store.scan(tenant, miss.json().scan.scanId))?.result?.verdict, "PASS");
    await store.query("UPDATE cp_scans SET request_json=? WHERE scan_id=?", [JSON.stringify(initialScan.request), initialScan.scanId]);
    const read = (id: string) => app.inject({ url: `/v1/scans/${id}/attestation?validator=0x${"c".repeat(40)}`, headers });
    const inspectionsBeforeApi = inspections.length;
    assert.equal((await read(selectedScan.scanId)).json().verdict, "PASS"); assert.equal((await read(initialScan.scanId)).json().verdict, "PASS");
    assert.equal(inspections.length, inspectionsBeforeApi, "API has no Docker export path");
    const publicScan = await app.inject({ url: `/v1/scans/${selectedScan.scanId}`, headers });
    assert.equal(publicScan.json().scan.baselineReleaseId, before.identity.releaseId);
    assert.doesNotMatch(publicScan.body, /sourceBudget|sourceProvenance|scopedConfigHash|127\.0\.0\.1|private\.json/);
    // Queue with known authority, then withdraw only the baseline before execution.
    const queued = await request("withdrawn", { baselineReleaseId: before.identity.releaseId }); assert.equal(queued.statusCode, 202, queued.body);
    await writeFile(current.apiProvenancePath, JSON.stringify({ ...current.catalogue, artifacts: [current.sourceProvenance] }));
    const count = executed; await runPreparationWorkerOnce(store, options); assert.equal(executed, count);
    assert.equal((await preparations(store, tenant, queued.json().preparation.preparationId))[0].status, "DEAD_LETTER");
    assert.equal((await read(selectedScan.scanId)).json().error.code, "SCOPED_OPERATOR_PROVENANCE_REQUIRED");
    assert.equal((await read(initialScan.scanId)).json().verdict, "PASS", "explicit no-baseline scan does not depend on other catalogue entries");
    await writeFile(current.apiProvenancePath, JSON.stringify(current.catalogue));
    // New config forces a rescan, then deletion during execution prevents final publication.
    options.scopedPrepared.ai.timeoutMs++;
    const mid = await rescan("mid-scan", { baselineReleaseId: before.identity.releaseId }); assert.equal(mid.json().reusedResult, false, mid.body);
    duringScan = async () => { await writeFile(current.apiProvenancePath, JSON.stringify({ ...current.catalogue, artifacts: [current.sourceProvenance] })); };
    await runControlWorkerOnce(store, options); duringScan = undefined;
    assert.equal((await store.scan(tenant, mid.json().scan.scanId))?.status, "DEAD_LETTER");
    assert.equal((await store.scan(tenant, mid.json().scan.scanId))?.result, undefined);
    await writeFile(current.apiProvenancePath, JSON.stringify(current.catalogue));
    const runtimeChanged = await request("changed-runtime", { baselineReleaseId: before.identity.releaseId });
    assert.equal(runtimeChanged.statusCode, 202, runtimeChanged.body);
    const inspect = options.inspectPreparedRuntime, beforeRuntimeAttempt = executed;
    options.inspectPreparedRuntime = async (input: any) => ({ ...await inspect(input),
      ...(input.descriptor.sourceTreeDigest === before.source.artifactDigest ? { closureDigest: sha("changed actual baseline bytes") } : {}) });
    try { await runPreparationWorkerOnce(store, options); } finally { options.inspectPreparedRuntime = inspect; }
    assert.equal(executed, beforeRuntimeAttempt, "changed actual baseline export is rejected before scanner/provider invocation");
    assert.equal((await preparations(store, tenant, runtimeChanged.json().preparation.preparationId))[0].lastError?.code, "SCOPED_BASELINE_RUNTIME_CHANGED");
    // The scanner already returned valid evidence; authority is removed only at the final SQL boundary.
    options.scopedPrepared.ai.timeoutMs++;
    const finalizing = await rescan("finalize-withdrawn", { baselineReleaseId: before.identity.releaseId }); assert.equal(finalizing.json().reusedResult, false, finalizing.body);
    const transaction = store.forTenant.bind(store); let withdrew = false;
    store.forTenant = async (id, callback) => {
      if (!withdrew) { withdrew = true; await writeFile(current.apiProvenancePath, JSON.stringify({ ...current.catalogue, artifacts: [current.sourceProvenance] })); }
      return transaction(id, callback);
    };
    try { await runControlWorkerOnce(store, options); } finally { store.forTenant = transaction; }
    assert.equal(withdrew, true);
    const rejectedFinalization = (await store.scan(tenant, finalizing.json().scan.scanId))!;
    assert.equal(rejectedFinalization.status, "DEAD_LETTER"); assert.equal(rejectedFinalization.result, undefined);
    assert.equal(rejectedFinalization.lastError?.code, "SCOPED_OPERATOR_PROVENANCE_REQUIRED");
    await writeFile(current.apiProvenancePath, JSON.stringify(current.catalogue));
    await assert.rejects(scopedPreparationContext(options, "other-tenant", policy, source, store, before.identity.releaseId));
    await assert.rejects(scopedPreparationContext(options, tenant, policy, source, store, current.identity.releaseId), /BASELINE_IDENTITY_MISMATCH/);
    assert.ok(inspections.includes(before.source.artifactDigest), "worker separately exported selected baseline image");
});
