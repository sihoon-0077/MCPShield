import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { canonicalJson, createEvidenceBundle } from '../../services/scanner/src/evidence.mjs';
import { randomUUID } from 'node:crypto';
import { createOciRuntimeCatalogue } from '../../services/scanner/src/oci-coverage.mjs';
import { reconstructOciSemanticSources, verifyOciSemanticReview } from '../../services/scanner/src/oci-sources.mjs';
import { reviewPreparedSemantics } from '../../services/scanner/src/prepared-review.mjs';
import { scanOciRuntime } from '../../services/scanner/src/oci-scan.mjs';
import { readTrustedOciRuntime } from '../../services/scanner/src/oci-trust.mjs';
import { readOciObservationPolicy } from '../../services/scanner/src/oci-observer.mjs';
import { assessOciPolicy, ociSandboxFindings } from '../../services/scanner/src/oci-policy.mjs';
import { ociExecutionPolicy, createOciReleaseBinding } from '../../services/scanner/src/oci-binding.mjs';
import { assessTrivyDocuments } from '../../services/scanner/src/oci-trivy.mjs';
import { validateProbePlan } from '../../services/scanner/src/probes.mjs';
import { toolSurfaceHash } from '../../services/scanner/src/tool-surface.mjs';
import { ociHash, hashOciRuntimeDescriptor, OCI_OBSERVATION_POLICY, OCI_SOURCE_BUDGET_PROFILE } from '../../services/resolver/src/oci-runtime-descriptor.mjs';

const digest = ociHash('synthetic fixture identity'), platform = { os: 'linux', architecture: 'amd64' };
const entry = (path, text) => ({ path, type: 'File', mode: 0o555, uid: 0, gid: 0, link: null, digest: ociHash(text) });
function evidence() {
  const base = [entry('runner', Buffer.from([0, 1, 2, 3])), entry('removed.txt', 'removed base text')];
  const catalogue = createOciRuntimeCatalogue({ baseImageDigest: ociHash('authored-base-image'), platform, filesystem: { entries: base, digest: ociHash(canonicalJson(base)) } });
  const text = 'print("inert authored source, never imported by test")\n';
  const sources = ['server.py', 'MCP_TOOLS_COMPLETE.json'].map((path) => ({ path, digest: ociHash(text), contentBase64: Buffer.from(text).toString('base64') }));
  const entries = [base[0], ...sources.map(({ path }) => entry(path, text))].sort((a, b) => a.path.localeCompare(b.path));
  const inventory = { entries, digest: ociHash(canonicalJson(entries)) };
  const runtime = { argv: ['/runner', '/server.py'], workingDirectory: '/', environment: [] };
  const descriptor = { schemaVersion: 'mcpshield.oci-runtime.v1', profile: 'oci-container-v1', stage: 'OBSERVED',
    budgetProfile: OCI_SOURCE_BUDGET_PROFILE, sourceBytes: 1000, layerArchiveBytes: 2048, exportArchiveBytes: 2048,
    sourceTreeDigest: digest, sourceIndexDigest: digest, manifestDigest: digest, configDigest: digest, platform,
    finalImageDigest: digest, imageDigestKind: 'DOCKER_IMAGE_CONFIG_ID', rootfsDigest: inventory.digest,
    entrypoint: { requestedPath: '/runner', resolvedPath: '/runner', contentDigest: base[0].digest, linkChainDigest: digest },
    argv: runtime.argv, workingDirectory: runtime.workingDirectory, environmentDigest: ociHash('[]'),
    toolSurfaceHash: '0x' + 'b'.repeat(64), policy: OCI_OBSERVATION_POLICY };
  return { descriptor, privateEvidence: { access: 'ENCRYPTED_OPERATOR_EVIDENCE_ONLY', catalogue, inventory, sources, runtime } };
}

test('OCI semantic input reconstructs exact original bytes and full structural diff including deleted base entries', () => {
  const fixture = evidence(), reconstructed = reconstructOciSemanticSources(fixture.descriptor, fixture.privateEvidence);
  assert.equal(reconstructed.files.length, 3);
  assert.equal(reconstructed.files[0].path, 'oci/structure.json');
  assert.ok(reconstructed.files.some(({ path }) => path === 'oci/source/MCP_TOOLS_COMPLETE.json'));
  assert.equal(reconstructed.structure.changes.find(({ path }) => path === 'removed.txt').after, null);
  assert.equal(reconstructed.structure.baseRootfsDigest, fixture.privateEvidence.catalogue.rootfsDigest);
  assert.equal(reconstructed.structure.imageRootfsDigest, fixture.descriptor.rootfsDigest);
  for (const mutate of [(p) => p.sources.pop(), (p) => p.sources.push(p.sources[0]),
    (p) => p.sources[0].contentBase64 = Buffer.from('forged benign text').toString('base64'),
    (p) => p.sources[0].contentBase64 += 'invalid', (p) => p.inventory.entries[0].mode = 0o777,
    (p) => p.runtime.environment = ['LANG=CHANGED'], (p) => p.catalogue.entries[0].uid = 999]) {
    const changed = structuredClone(fixture.privateEvidence); mutate(changed);
    assert.throws(() => reconstructOciSemanticSources(fixture.descriptor, changed), /OCI_/);
  }
  const omitted = structuredClone(fixture.privateEvidence); omitted.sources[0].contentBase64 = null;
  assert.equal(reconstructOciSemanticSources(fixture.descriptor, omitted).coverage.sourceClassificationComplete, false);
});

test('independent OCI reconstruction and policy reject rewritten source, omitted coverage, unbound effects and stripped local-test provenance', async () => {
  const server = createServer(async (request, response) => {
    for await (const _chunk of request) { /* authored local contract test, not paid model evidence */ }
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ riskClaims: [],
      semanticDiff: { purposeChanged: false, dataScopeExpanded: false, newHiddenObligation: false }, needsHumanReview: false }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const fixture = evidence(), { files } = reconstructOciSemanticSources(fixture.descriptor, fixture.privateEvidence);
    const releaseId = 'synthetic@1.0.0', tools = [{ name: 'synthetic', inputSchema: { type: 'object' } }];
    const semantic = await reviewPreparedSemantics({ files, tools, releaseId, profile: 'restricted-oci-offline-v1',
      ai: { allowRemoteAi: true, provider: 'custom', disclosurePolicy: 'LOCAL_CONTRACT_TEST', url: `http://127.0.0.1:${server.address().port}`, timeoutMs: 1000 } });
    const check = (review = semantic, inputFiles = files, inputTools = tools) => verifyOciSemanticReview({ semantic: review, files: inputFiles, tools: inputTools, releaseId });
    assert.deepEqual(check(), { semanticComplete: true, independentCriticComplete: true, semanticNoUnresolvedRisk: true });
    for (const mutate of [(s) => s.reviews[0].input.excerpts[0].content = 'fake clean input',
      (s) => delete s.disclosure, (s) => delete s.reviews[0].analyzer.execution.disclosure,
      (s) => delete s.reviews[0].critic, (s) => s.sources[0].rawDigest = digest,
      (s) => s.semanticProfile = 'restricted-node-docker-v1', (s) => s.reviews[0].critic.execution.schemaName = 'mcpshield_prepared_critic',
      (s) => s.reviews[0].input.releaseId = 'different@1.0.0', (s) => s.reviews[0].input.excerpts[0].offset = 1]) {
      const changed = structuredClone(semantic); mutate(changed); assert.equal(check(changed).semanticNoUnresolvedRisk, false);
    }
    const changedFiles = structuredClone(files); changedFiles[0].content += 'changed structure';
    assert.equal(check(semantic, changedFiles).semanticComplete, false);
    assert.equal(check(semantic, files, [{ ...tools[0], description: 'new tool metadata' }]).semanticComplete, false);

    // Synthetic pure-policy contract only. This locally authored trust object is
    // NOT a substitute for readTrustedOciRuntime or independent Docker replay.
    const policy = await readOciObservationPolicy(digest), reconstructed = reconstructOciSemanticSources(fixture.descriptor, fixture.privateEvidence);
    const anchors = { baseImageDigest: fixture.privateEvidence.catalogue.baseImageDigest, baseCatalogueDigest: fixture.privateEvidence.catalogue.catalogueDigest,
      trivyImageDigest: digest, databaseDigest: digest, observerDigest: policy.collectorDigest, sinkImageDigest: digest, sinkCodeDigest: policy.sinkCodeDigest };
    const descriptor = { ...fixture.descriptor, toolSurfaceHash: toolSurfaceHash(tools) };
    const binding = createOciReleaseBinding({ sourceReleaseId: '0x' + 'a'.repeat(64), descriptor, executionPolicy: ociExecutionPolicy(anchors) });
    const preparationDigest = hashOciRuntimeDescriptor({ ...descriptor, stage: 'IMPORTED', toolSurfaceHash: null });
    const database = { updatedAt: new Date(Date.now() - 1000).toISOString(), nextUpdate: new Date(Date.now() + 3600_000).toISOString(), maxAgeHours: 24 };
    const trusted = { anchors, descriptorDigest: binding.descriptorDigest, finalImageDigest: descriptor.finalImageDigest,
      rootfsDigest: descriptor.rootfsDigest, platform, observationPolicy: policy, database };
    const step = { source: 'LIVE_DOCKER_EXTERNAL_MCP_CLIENT', runtimeDigest: preparationDigest, canaryHashes: [], canaryTypes: [],
      undeclaredEgress: false, eventBodyLimit: false, eventCount: 0, mcp: { complete: true, toolSurfaceHash: descriptor.toolSurfaceHash,
        pages: 1, protocolVersion: '2025-03-26', receivedBytes: 100, callResults: [{ name: 'synthetic', isError: false, contentHash: digest }] } };
    const observation = { profile: 'oci-container-v1', source: 'LIVE_DOCKER_EXTERNAL_MCP_CLIENT', preparationDescriptorDigest: preparationDigest,
      observedDescriptorDigest: binding.descriptorDigest, executionPolicyDigest: ociHash(canonicalJson(policy)), issues: [],
      steps: { discovery: { ...step, mcp: { ...step.mcp, callResults: [] } }, normal: step, adversarial: structuredClone(step) },
      scenarios: validateProbePlan({ scenarios: ['NORMAL', 'ADVERSARIAL'].map((kind) => ({ scenarioId: kind.toLowerCase(), kind,
        goal: 'Authored synthetic task', toolName: 'synthetic', argumentsJson: '{}' })) }, tools).scenarios };
    const documents = [anchors.baseImageDigest, binding.finalImageDigest].map((imageDigest) => ({ imageDigest, archiveDigest: digest,
      report: { SchemaVersion: 2, ArtifactType: 'container_image', Metadata: { ImageID: imageDigest },
        Results: [{ Packages: [{ Name: 'synthetic-base', Version: '1.0.0' }] }] },
      sbom: { bomFormat: 'CycloneDX', specVersion: '1.6', components: [{ name: 'synthetic-base', version: '1.0.0' }] } }));
    const vulnerability = { source: 'LIVE_OFFLINE_TRIVY_CONTAINER', toolImageDigest: anchors.trivyImageDigest,
      databaseDigest: anchors.databaseDigest, database, images: documents.map((doc) => assessTrivyDocuments(doc.report, doc.sbom, doc.imageDigest)) };
    const review = { image: { descriptorDigest: preparationDigest, finalImageDigest: descriptor.finalImageDigest, rootfsDigest: descriptor.rootfsDigest },
      coverage: reconstructed.coverage, vulnerability, issues: [] };
    const result = { schemaVersion: '1.0.0', scanId: randomUUID(), releaseId, artifactDigest: binding.artifactDigest,
      toolSurfaceHash: binding.toolSurfaceHash, scanStatus: 'PASSED', findings: [], evidenceHash: '0x' + ociHash('[]').slice(7), source: 'LIVE' };
    const docs = { 'oci/binding.json': binding, 'runtime/oci-descriptor.json': descriptor, 'runtime/execution-policy.json': binding.executionPolicy,
      'runtime/observation-policy.json': policy, 'runtime/tools.json': tools, 'oci/observation.json': observation,
      'oci/private-image-evidence.json': { ...fixture.privateEvidence, trivy: { access: 'ENCRYPTED_OPERATOR_EVIDENCE_ONLY', documents } },
      'oci/source-reconstruction.json': { semanticInputDigest: reconstructed.semanticInputDigest, sourceBytes: reconstructed.sourceBytes,
        coverage: reconstructed.coverage, structureDigest: ociHash(canonicalJson(reconstructed.structure)) },
      'oci/image-review.json': { ...review, reviewDigest: ociHash(canonicalJson(review)) }, 'semantic/reviews.json': semantic,
      'report.json': { ...result, scope: 'RESTRICTED_OCI_OFFLINE_V1' } };
    const assess = (d = docs, r = result, local = trusted) => assessOciPolicy(createEvidenceBundle(d), r, binding, local);
    assert.equal(assess().verdict, 'PASS', JSON.stringify(assess()));
    assert.equal(assess().semanticEvidenceMode, 'LOCAL_CONTRACT_TEST');
    assert.equal(assess().fullBehaviorCoverage, false);
    for (const mutate of [(d) => d['oci/private-image-evidence.json'].sources.pop(),
      (d) => d['oci/private-image-evidence.json'].sources[0].contentBase64 = Buffer.from('forged benign code').toString('base64'),
      (d) => d['semantic/reviews.json'].reviews[0].critic = null, (d) => delete d['semantic/reviews.json'].disclosure,
      (d) => d['oci/private-image-evidence.json'].trivy.documents[0].sbom.components = [],
      (d) => d['oci/observation.json'].steps.normal.mcp.callResults = [],
      (d) => d['oci/observation.json'].steps.normal.runtimeDigest = digest]) {
      const changed = structuredClone(docs); mutate(changed); assert.equal(assess(changed).verdict, 'ABSTAIN');
    }
    assert.equal(assess(docs, result, {}).verdict, 'ABSTAIN');
    const leaked = structuredClone(docs), effect = leaked['oci/observation.json'].steps.adversarial;
    effect.canaryHashes = ['c'.repeat(64)]; effect.eventCount = 1;
    leaked['oci/observation.json'].steps.normal.canaryHashes = ['d'.repeat(64)];
    leaked['oci/observation.json'].steps.normal.eventCount = 1;
    const findings = ociSandboxFindings(leaked['oci/observation.json']);
    assert.deepEqual(findings, ociSandboxFindings(JSON.parse(canonicalJson(leaked['oci/observation.json']))));
    assert.deepEqual(findings.map(({ evidence }) => evidence.observationStage), ['normal', 'adversarial']);
    const failed = { ...result, scanStatus: 'FAILED', findings, evidenceHash: '0x' + ociHash(canonicalJson(findings)).slice(7) };
    leaked['report.json'] = { ...failed, scope: 'RESTRICTED_OCI_OFFLINE_V1' };
    assert.equal(assess(leaked, failed).verdict, 'FAIL');
    effect.runtimeDigest = digest;
    assert.equal(assess(leaked, failed).verdict, 'ABSTAIN');
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test('OCI scan orchestration rejects unbound identities and missing local trust before execution', async () => {
  const { descriptor } = evidence();
  const input = { descriptor, expectedDescriptorDigest: hashOciRuntimeDescriptor(descriptor),
    sourceReleaseId: '0x' + '1'.repeat(64), releaseId: 'synthetic@1.0.0',
    trust: { baseImageDigest: digest, trivyImageDigest: digest, databaseDigest: digest, sinkImageDigest: digest } };
  for (const changed of [{ ...input, expectedDescriptorDigest: ociHash('wrong') }, { ...input, trust: {} },
    { ...input, sourceReleaseId: digest }, { ...input, releaseId: 'arbitrary' }, { ...input, scanId: 'arbitrary' },
    { ...input, timeoutMs: 0 }, { ...input, reviewTimeoutMs: 180001 }]) {
    await assert.rejects(() => scanOciRuntime(changed), /OCI_SCAN_INPUT_INVALID/);
  }
  await assert.rejects(() => readTrustedOciRuntime({ descriptor, expectedDescriptorDigest: input.expectedDescriptorDigest, trust: {} }), /LOCAL_TRUST_INPUT_INVALID/);
  await assert.rejects(() => readTrustedOciRuntime({ descriptor, expectedDescriptorDigest: ociHash('wrong'), trust: input.trust }), /LOCAL_TRUST_INPUT_INVALID/);
});
