import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { canonicalJson, createEvidenceBundle } from '../../services/scanner/src/evidence.mjs';
import { scopedReviewPolicy, scopedBaselineReviewPolicy, validateScopedReviewPolicy, validateScopedBaselineReviewPolicy,
  SCOPED_LIMITS, SCOPED_DISCLOSURE_POLICY } from '../../services/scanner/src/scoped-policy.mjs';
import { buildScopedSemanticInputV2, buildScopedSemanticInputV21, verifyScopedSemanticInputV21,
  reviewScopedSemanticsV21 } from '../../services/scanner/src/scoped-semantic.mjs';
import { scopedPreparedExecutionPolicy, createPreparedReleaseBinding } from '../../services/scanner/src/prepared-binding.mjs';
import { scopedBaselineCommitment, comparePreparedClosures, checkedScopedBaselineAuthority, preparedClosureEvidence, checkedPreparedBaselineEvidence } from '../../services/scanner/src/scoped-baseline.mjs';
import { assessScopedPreparedPolicy, assessScopedPreparedPolicyV21 } from '../../services/scanner/src/prepared-policy.mjs';
import { scopedOciExecutionPolicy } from '../../services/scanner/src/oci-binding.mjs';
import { closureManifest } from '../../services/resolver/src/closure-files.mjs';
import { toolSurfaceHash } from '../../services/scanner/src/tool-surface.mjs';
import { exactReleaseIdentity } from '../../packages/contracts-sdk/src/v2-identity.mjs';
import { hashPreparedRuntimeDescriptor } from '../../services/resolver/src/runtime-descriptor.mjs';
import { inspectPreparedSources } from '../../services/scanner/src/prepared-review.mjs';
import { probeArgumentsDigest } from '../../services/scanner/src/mcp-probe.cjs';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { authoredMailbox } from './helpers/scoped-mailbox.mjs';
import { prepareAndScanRuntime, scanPreparedRuntime, readTrustedPreparedRuntime, readTrustedPreparedIdentity } from '../../services/scanner/src/prepared-scan.mjs';
import { artifactDigest } from '../../services/scanner/src/scanner.mjs';
import { removeFixtureSnapshot } from '../../services/scanner/src/snapshot.mjs';

const sha = value => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const digest = sha('synthetic commitment only, not Docker execution');
const padding = '// authored harmless review fixture padding zzzz\n'.repeat(70);
const tools = [{ name: 'list_messages', description: 'Read the synthetic inbox.', inputSchema: { type: 'object',
  properties: { limit: { type: 'integer', minimum: 1, maximum: 10 } }, required: ['limit'], additionalProperties: false } }];
const policy = semantic => scopedPreparedExecutionPolicy({ collectorDigest: digest, observerDigest: digest, egressAllowHosts: [] }, semantic);
const provenance = sourceArtifactDigest => ({ schemaVersion: 'mcpshield.operator-code-artifact.v1',
  authority: 'OPERATOR_LOCAL_CATALOG', contentClass: 'CODE_ARTIFACT_NO_CUSTOMER_DATA', sourceArtifactDigest });
const identity = (name, artifactDigest) => {
  const input = { toolId: `npm:${name}`, artifactDigest, manifestDigest: sha(name), toolSurfaceHash: toolSurfaceHash(tools) };
  return { ...input, ...exactReleaseIdentity(input) };
};
function selectedBaseline(sourceIdentity, semantic = scopedReviewPolicy('LOCAL_CONTRACT_TEST')) {
  const descriptor = { schemaVersion: 'mcpshield.prepared-runtime.v1', stage: 'CLOSURE_PREPARED', profile: 'npm-closure-v1',
    sourceDigest: sourceIdentity.artifactDigest, sourceTreeDigest: sourceIdentity.artifactDigest, lockDigest: digest, lockOrigin: 'SUPPLIED',
    builderImageDigest: digest, platform: { os: 'linux', architecture: 'amd64' }, finalImageDigest: digest, toolSurfaceHash: toolSurfaceHash(tools),
    entrypoint: { path: 'server.js', digest }, argv: ['/usr/local/bin/node', '/app/server.js'],
    policy: { acquisitionNetwork: 'REGISTRY_ONLY_SEPARATE', installNetwork: 'NONE', installScripts: 'DISABLED',
      executionNetwork: 'INTERNAL_SYNTHETIC_PROXY', user: 'NON_ROOT', rootFilesystem: 'READ_ONLY' } };
  const binding = createPreparedReleaseBinding({ sourceReleaseId: sourceIdentity.releaseId, descriptor, executionPolicy: policy(semantic) });
  return { releaseId: exactReleaseIdentity({ toolId: sourceIdentity.toolId, ...binding }).releaseId, sourceIdentity, binding,
    sourceProvenance: provenance(sourceIdentity.artifactDigest) };
}
const emptyComparison = (current = digest, before = digest) => ({ schemaVersion: 'mcpshield.prepared-package-diff.v1',
  baselineProvided: before !== null, comparison: before === null ? 'NO_BASELINE_NOT_AN_UPDATE_COMPARISON' : 'INSTALLED_CLOSURE_AND_DISCOVERED_TOOLS',
  currentClosureDigest: current, baselineClosureDigest: before, tools: [], dependencies: [], installedDependencies: [], installScripts: [], egressPolicy: [] });
function input(code = 'fetch("https://mail-api.local/messages");') {
  const files = [{ path: 'server.js', content: padding + code + padding }], sourceArtifactDigest = sha('current source');
  return { files, tools: structuredClone(tools), executionPolicy: policy(scopedBaselineReviewPolicy('LOCAL_CONTRACT_TEST')),
    sourceArtifactDigest, sourceIdentity: identity('synthetic', sourceArtifactDigest), sourceProvenance: provenance(sourceArtifactDigest),
    runtime: { profile: 'restricted-node-docker-v2', runtimeDigest: digest, environmentDigest: digest }, comparison: emptyComparison(),
    baseline: { ...selectedBaseline(identity('synthetic', sha('previous source'))), files: structuredClone(files),
      tools: structuredClone(tools), closureDigest: digest } };
}
const clean = { riskClaims: [], semanticDiff: { purposeChanged: false, dataScopeExpanded: false, newHiddenObligation: false }, needsHumanReview: false };
async function provider(context, override) {
  const requests = [], server = createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks)); requests.push(body);
    const dto = JSON.parse(body.input[0].content.split('\n').at(-1));
    const output = override?.(body, dto) ?? (body.text.format.name.endsWith('_probe') ? { scenarios: ['NORMAL', 'ADVERSARIAL'].flatMap(kind =>
      Array.from({ length: dto.minimumScenariosPerKind }, (_, index) => ({ scenarioId: `${kind.toLowerCase()}-${index}`, kind, goal: 'Synthetic scope only.',
        toolName: 'list_messages', argumentsJson: JSON.stringify({ limit: index + 1 }) }))) } : clean);
    response.end(JSON.stringify({ status: 'completed', model: body.model, output: [{ type: 'message', role: 'assistant',
      content: [{ type: 'output_text', text: JSON.stringify(output) }] }] }));
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  context.after(() => { server.closeAllConnections(); server.close(); });
  return { requests, ai: { allowRemoteAi: true, provider: 'openai', url: `http://127.0.0.1:${server.address().port}`,
    disclosurePolicy: SCOPED_DISCLOSURE_POLICY, evidenceMode: 'LOCAL_CONTRACT_TEST', model: 'synthetic-primary',
    analyzer2: { model: 'synthetic-secondary' }, token: 'SYNTHETIC_LOCAL_ONLY', timeoutMs: 1000 } };
}

test('2.1 is explicit; v2.0 policy golden hashes and old-domain rejection are preserved', () => {
  // These golden hashes were calculated from Main 5bad1e9, not from the new factory.
  for (const [mode, expected] of [['LOCAL_CONTRACT_TEST', 'ca38d9055bea43abc217e060935b82a5eecfea6e209c68362ab843d5925b2fc7'],
    ['PROVIDER_EXECUTION', 'b64838a6b6ab45cbd10fe469900908abf264728588b871c1aabda76fb51d3373']]) {
    assert.equal(sha(canonicalJson(scopedReviewPolicy(mode))), `sha256:${expected}`);
    const current = scopedBaselineReviewPolicy(mode);
    assert.equal(validateScopedReviewPolicy(current), false);
    assert.equal(validateScopedBaselineReviewPolicy(current), true);
    assert.equal(validateScopedBaselineReviewPolicy({ ...current, baseline: { ...current.baseline, currentCoverage: 'DIFF_ONLY' } }), false);
    assert.throws(() => scopedOciExecutionPolicy({}, current), /OCI_SCOPED_POLICY_INVALID/);
    assert.notEqual(sha(canonicalJson(current)), `sha256:${expected}`);
  }
  const original = input();
  assert.throws(() => buildScopedSemanticInputV2(original), /EXECUTION_POLICY_INVALID/);
  assert.throws(() => buildScopedSemanticInputV21({ ...original, executionPolicy: policy(scopedReviewPolicy('LOCAL_CONTRACT_TEST')) }), /BASELINE_POLICY_REQUIRED/);
  assert.throws(() => buildScopedSemanticInputV21({ ...original, baseline: undefined }), /BASELINE_SELECTION_INVALID/);
  assert.throws(() => buildScopedSemanticInputV21({ ...original, packageDiff: {} }), /INPUT_FIELDS_INVALID/);
  assert.throws(() => buildScopedSemanticInputV21({ ...original, runtime: { ...original.runtime, profile: 'restricted-oci-offline-v2' } }), /RUNTIME_METADATA_INVALID/);
  const first = buildScopedSemanticInputV21({ ...original, baseline: null, comparison: emptyComparison(digest, null) });
  assert.equal(first.input.baseline, null); assert.equal(first.proof.baselineProvided, false);
  assert.equal(first.input.comparison, 'NO_BASELINE_NOT_AN_UPDATE_COMPARISON');
  assert.deepEqual(first.input.changes, []);
  assert.ok(first.input.excerpts.length, 'first release still reviews current risk');
});

test('identical baseline never removes current risk selection; changing before bytes is bound to proof', () => {
  const original = input(), selected = buildScopedSemanticInputV21(original);
  assert.equal(selected.proof.scopeComplete, true, JSON.stringify(selected.proof.issues));
  assert.equal(selected.proof.baselineProvided, true); assert.deepEqual(selected.input.changes, []);
  assert.equal(selected.input.comparison, 'PINNED_BASELINE_NO_APPROVAL_INHERITANCE');
  assert.equal(selected.input.packageDiff.comparison, 'INSTALLED_CLOSURE_AND_DISCOVERED_TOOLS');
  assert.ok(selected.proof.union.selections.some(item => item.side === 'after' && item.ranges.length));
  assert.equal(selected.input.tier, 2);
  assert.equal(verifyScopedSemanticInputV21({ ...original, ...selected }), true);
  const modified = structuredClone(original); modified.baseline.files[0].content = padding + 'fetch("https://old-mail.local/old");' + padding;
  const changed = buildScopedSemanticInputV21(modified);
  assert.equal(changed.input.changes[0].kind, 'MODIFIED');
  assert.deepEqual(changed.proof.union.selections.map(item => item.side), ['before', 'after']);
  assert.equal(verifyScopedSemanticInputV21({ ...modified, ...selected }), false);
  const previousRisk = input('const count = 1;'); previousRisk.baseline.files[0].content = padding + 'eval("authored fixture only");' + padding;
  assert.equal(buildScopedSemanticInputV21(previousRisk).input.tier, 3);
});

test('exact source, tool, runtime surface, operator scope and baseline selection cannot be substituted', () => {
  for (const mutate of [
    value => value.baseline.releaseId = `0x${'f'.repeat(64)}`,
    value => Object.assign(value.baseline, selectedBaseline(identity('other-tool', sha('previous source')))),
    value => Object.assign(value.baseline, selectedBaseline(value.sourceIdentity)),
    value => value.baseline.binding.finalImageDigest = sha('other image'),
    value => value.baseline.sourceIdentity.artifactDigest = sha('other source'),
    value => value.baseline.sourceProvenance.authority = 'API_DECLARATION',
    value => value.baseline.tools[0].description = 'Different surface.',
    value => value.baseline.publisher = { status: 'VALID' },
    value => value.sourceIdentity.manifestDigest = sha('other manifest'),
  ]) {
    const original = input(); mutate(original);
    assert.throws(() => buildScopedSemanticInputV21(original), /SCOPED_/, String(mutate));
  }
});

test('combined source/disclosure budgets and baseline unknown classification cause zero provider requests', async context => {
  const { ai, requests } = await provider(context);
  const tooLarge = input();
  tooLarge.files[0].content = 'x'.repeat(SCOPED_LIMITS.localSourceBytes / 2 + 1);
  tooLarge.baseline.files[0].content = tooLarge.files[0].content;
  await assert.rejects(reviewScopedSemanticsV21({ ...tooLarge, ai }), /COMBINED_SOURCE_LIMIT/);
  for (const mutate of [value => value.baseline.files[0].path = 'unknown.dat',
    value => value.files = [],
    value => { value.files[0].content = 'fetch("short");'; },
    value => { value.tools[0].description = value.files[0].content; }]) {
    const original = input(); mutate(original);
    assert.equal((await reviewScopedSemanticsV21({ ...original, ai })).scopeComplete, false);
  }
  assert.equal(requests.length, 0);
});

test('baseline descriptions, schema keys and annotations cannot smuggle whole source after valid surface rebinding', async context => {
  const { ai, requests } = await provider(context);
  for (const place of ['description', 'schema-key', 'annotation']) {
    const original = input(), tool = original.baseline.tools[0], content = original.baseline.files[0].content;
    if (place === 'description') tool.description = content;
    if (place === 'schema-key') tool.inputSchema.properties[content] = { type: 'string' };
    if (place === 'annotation') tool.annotations = { title: content };
    original.baseline.binding = createPreparedReleaseBinding({ sourceReleaseId: original.baseline.binding.sourceReleaseId,
      descriptor: { ...original.baseline.binding.descriptor, toolSurfaceHash: toolSurfaceHash(original.baseline.tools) },
      executionPolicy: original.baseline.binding.executionPolicy });
    original.baseline.releaseId = exactReleaseIdentity({ toolId: original.sourceIdentity.toolId, ...original.baseline.binding }).releaseId;
    const reviewed = await reviewScopedSemanticsV21({ ...original, ai });
    assert.equal(reviewed.scopeComplete, false, place);
    assert.ok(reviewed.issues.includes('SCOPED_DISCLOSURE_UNION_EXCEEDED'), place);
  }
  assert.equal(requests.length, 0);
});

test('actual local HTTP uses one immutable before/after DTO for blind roles and validated current-tool probes', async context => {
  const { ai, requests } = await provider(context), original = input('eval("authored fixture only");');
  const review = await reviewScopedSemanticsV21({ ...original, ai });
  assert.equal(review.scopeComplete, true, JSON.stringify(review.issues));
  assert.equal(review.approvalVerdict, 'ABSTAIN'); assert.equal(review.evidenceMode, 'LOCAL_CONTRACT_TEST');
  assert.equal(review.schemaVersion, 'mcpshield.scoped-semantic-review.v2.1');
  assert.equal(requests.length, 4);
  for (const body of requests) {
    const dto = JSON.parse(body.input[0].content.split('\n').at(-1)); delete dto.citations;
    assert.equal(canonicalJson(dto), canonicalJson(review.input));
    assert.match(body.text.format.name, /^mcpshield_scoped_v2_1_/);
    assert.deepEqual(body.tools, []); assert.equal(body.store, false);
    assert.equal(body.input[0].content.includes('riskClaims'), false, 'no previous role output');
    assert.equal(body.input[0].content.includes(original.files[0].content), false);
  }
});

test('normal update and scope-expansion contract responses retain cited baseline evidence without claiming provider quality', async context => {
  const { ai } = await provider(context, (body, dto) => !body.text.format.name.endsWith('_probe') && dto.baselineTools[0].description.includes('Previous')
    ? { riskClaims: [{ category: 'PRIVILEGE_EXPANSION', severity: 'MEDIUM', confidence: 0.7,
      evidence: [dto.citations.find(span => span.source === 'baselineTools.0.description')],
      explanation: 'Synthetic response: compare prior mailbox scope with current access.', recommendedProbe: 'Use a synthetic mailbox only.' }],
      semanticDiff: { purposeChanged: false, dataScopeExpanded: true, newHiddenObligation: false }, needsHumanReview: true } : undefined);
  const normal = await reviewScopedSemanticsV21({ ...input(), ai });
  assert.equal(normal.noUnresolvedRisk, true); assert.equal(normal.approvalVerdict, 'ABSTAIN');
  const expanded = input(); expanded.baseline.tools[0].description = 'Previous read-only mailbox scope.';
  expanded.baseline.binding = createPreparedReleaseBinding({ sourceReleaseId: expanded.baseline.binding.sourceReleaseId,
    descriptor: { ...expanded.baseline.binding.descriptor, toolSurfaceHash: toolSurfaceHash(expanded.baseline.tools) },
    executionPolicy: expanded.baseline.binding.executionPolicy });
  expanded.baseline.releaseId = exactReleaseIdentity({ toolId: expanded.sourceIdentity.toolId, ...expanded.baseline.binding }).releaseId;
  const review = await reviewScopedSemanticsV21({ ...expanded, ai });
  assert.equal(review.scopeComplete, true); assert.equal(review.noUnresolvedRisk, false);
  assert.equal(review.findings[0].evidence.spans[0].source, 'baselineTools.0.description');
  assert.equal(review.providerQuality, 'PROVIDER_QUALITY_NOT_MEASURED');
});

function closure(code, range = '^1.0.0') {
  const pkg = { name: 'synthetic', version: '1.0.0', dependencies: { dependency: range } };
  const documents = { 'package.json': JSON.stringify(pkg),
    'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': pkg, 'node_modules/dependency': { version: '1.0.0' } } }),
    'node_modules/dependency/package.json': JSON.stringify({ name: 'dependency', version: '1.0.0' }),
    'node_modules/dependency/index.js': code };
  const contents = Object.entries(documents).map(([path, content]) => ({ path, bytes: Buffer.from(content) }));
  return { ...closureManifest(contents.map(({ path, bytes }) => ({ path, type: 'File', mode: 0o444, digest: sha(bytes) }))),
    contents, bytes: contents.reduce((sum, entry) => sum + entry.bytes.length, 0) };
}
test('installed-byte comparison on synthetic inventories distinguishes same-version changes and no-baseline from updates', () => {
  const original = input(), before = closure('exports.value = 1;'), current = closure('exports.value = 2;', '^1.0.1');
  const compared = comparePreparedClosures({ current, tools, executionPolicy: original.executionPolicy,
    baseline: { closure: before, tools, executionPolicy: original.baseline.binding.executionPolicy } });
  assert.equal(compared.baselineProvided, true); assert.equal(compared.dependencies[0].after, '^1.0.1');
  assert.equal(compared.installedDependencies.length, 1);
  const changed = compared.installedDependencies[0];
  assert.equal(changed.before.version, changed.after.version);
  assert.equal(changed.before.packageJsonDigest, changed.after.packageJsonDigest);
  assert.notEqual(changed.before.installedContentDigest, changed.after.installedContentDigest);
  const first = comparePreparedClosures({ current, tools, executionPolicy: original.executionPolicy, baseline: null });
  assert.equal(first.baselineProvided, false); assert.deepEqual(first.dependencies, []); assert.deepEqual(first.installedDependencies, []);
  const tampered = structuredClone(before); tampered.contents[0].bytes = Buffer.from('{}');
  assert.throws(() => comparePreparedClosures({ current, tools, executionPolicy: original.executionPolicy,
    baseline: { closure: tampered, tools, executionPolicy: original.baseline.binding.executionPolicy } }));
});

test('new policy commitment or synthetic DTO cannot pass the old runtime aggregate', () => {
  const original = input(), selected = selectedBaseline(original.sourceIdentity, scopedBaselineReviewPolicy('LOCAL_CONTRACT_TEST'));
  const result = { schemaVersion: '1.0.0', scanId: randomUUID(), releaseId: 'synthetic@1.0.0', artifactDigest: selected.binding.artifactDigest,
    toolSurfaceHash: selected.binding.toolSurfaceHash, scanStatus: 'PASSED', findings: [], evidenceHash: `0x${'a'.repeat(64)}`, source: 'LIVE' };
  const assessed = assessScopedPreparedPolicy(createEvidenceBundle({ 'report.json': result }), result, selected.binding, {});
  assert.equal(assessed.verdict, 'ABSTAIN'); assert.deepEqual(assessed.issues, ['SCOPED_BASELINE_RUNTIME_NOT_INTEGRATED']);
  const { files, tools: previousTools, closureDigest, ...baseline } = original.baseline;
  assert.equal(scopedBaselineCommitment({ sourceIdentity: original.sourceIdentity, executionPolicy: original.executionPolicy, baseline }).releaseId, baseline.releaseId);
});

// These are authored byte inventories/observations, never claimed Docker runs.
function boundFixture(code, tag, semantic) {
  const pkg = { name: 'synthetic', version: '1.0.0', bin: 'server.js', description: 'z'.repeat(1500) };
  const documents = { 'package.json': JSON.stringify(pkg), 'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': pkg } }),
    'server.js': padding + code + padding };
  const contents = Object.entries(documents).map(([path, content]) => ({ path, bytes: Buffer.from(content) }));
  const closure = { ...closureManifest(contents.map(({ path, bytes }) => ({ path, type: 'File', mode: 0o444, digest: sha(bytes) }))),
    contents, bytes: contents.reduce((n, file) => n + file.bytes.length, 0), source: 'LIVE_DOCKER_IMAGE_EXPORT' };
  const sourceIdentity = identity('synthetic', sha(tag)), base = selectedBaseline(sourceIdentity, semantic);
  const descriptor = { ...base.binding.descriptor, finalImageDigest: sha(`image-${tag}`),
    entrypoint: { path: 'server.js', digest: sha(contents[2].bytes) }, lockDigest: sha(contents[1].bytes) };
  const binding = createPreparedReleaseBinding({ sourceReleaseId: sourceIdentity.releaseId, descriptor, executionPolicy: base.binding.executionPolicy });
  const sourceDescriptorDigest = hashPreparedRuntimeDescriptor({ ...descriptor, stage: 'PREFLIGHT', finalImageDigest: null, toolSurfaceHash: null });
  closure.report = { ...closureManifest(closure.entries), bytes: closure.bytes, sourceDescriptorDigest, installScripts: false, installNetwork: 'NONE' };
  const selection = { ...base, binding, releaseId: exactReleaseIdentity({ toolId: sourceIdentity.toolId, ...binding }).releaseId };
  const trusted = { builderImageDigest: digest, collectorDigest: digest, observerDigest: digest, finalImageDigest: binding.finalImageDigest,
    platform: descriptor.platform, closureDigest: closure.digest, sourceDescriptorDigest, entrypointDigest: descriptor.entrypoint.digest,
    sourceIdentity, sourceProvenance: selection.sourceProvenance, sourceBudget: { sourceArtifactDigest: sourceIdentity.artifactDigest, sourceBytes: closure.bytes },
    publisher: null, releaseId: selection.releaseId };
  const step = { protocolComplete: true, timedOut: false, exitCode: 0, failureCode: null, pages: 1, permissionProfile: 'NODE_PERMISSION_READ_ONLY_V1',
    runtimeIdentity: { imageDigest: descriptor.finalImageDigest, platform: descriptor.platform, argv: descriptor.argv },
    toolSurfaceHash: binding.toolSurfaceHash, egressEvents: [], canaryExfiltration: false, callResults: [] };
  return { closure, selection, trusted, step };
}

async function contractEvidence(ai, beforeCode = 'const count=1;') {
  const current = boundFixture('const count=2;', 'current', scopedBaselineReviewPolicy('LOCAL_CONTRACT_TEST'));
  const before = beforeCode === null ? null : boundFixture(beforeCode, 'before', scopedReviewPolicy('LOCAL_CONTRACT_TEST'));
  const { binding, sourceIdentity } = current.selection;
  const baselineDocument = before === null ? null : { schemaVersion: 'mcpshield.prepared-baseline-evidence.v1', selection: before.selection,
    publisher: before.trusted.publisher, closure: preparedClosureEvidence(before.closure), tools, discovery: before.step, observedAt: '2026-10-01T00:00:00.000Z' };
  const trusted = { ...current.trusted, baseline: before?.trusted ?? null };
  const context = { sourceIdentity, executionPolicy: binding.executionPolicy, baseline: before?.selection ?? null };
  const baseline = checkedPreparedBaselineEvidence(baselineDocument, context, trusted.baseline);
  const comparison = comparePreparedClosures({ current: current.closure, tools, executionPolicy: binding.executionPolicy,
    baseline: before === null ? null : { closure: before.closure, tools, executionPolicy: before.selection.binding.executionPolicy } });
  const inspected = inspectPreparedSources(current.closure);
  const semantic = await reviewScopedSemanticsV21({ ai, files: inspected.files, tools, sourceIdentity,
    sourceArtifactDigest: sourceIdentity.artifactDigest, sourceProvenance: trusted.sourceProvenance, executionPolicy: binding.executionPolicy,
    runtime: { profile: 'restricted-node-docker-v2', runtimeDigest: binding.finalImageDigest, environmentDigest: current.closure.digest },
    baseline: baseline?.semanticInput ?? null, comparison });
  assert.equal(semantic.scopeComplete, true, JSON.stringify(semantic.issues));
  const stage = kind => ({ ...current.step, callResults: semantic.reviews.probe.report.scenarios.filter(s => s.kind === kind).map(({ toolCall }) => ({
    name: toolCall.name, argumentsDigest: probeArgumentsDigest(toolCall.arguments), isError: false, contentHash: 'b'.repeat(64) })) });
  const result = { schemaVersion: '1.0.0', scanId: randomUUID(), releaseId: 'synthetic@1.0.0', artifactDigest: binding.artifactDigest,
    toolSurfaceHash: binding.toolSurfaceHash, scanStatus: 'PASSED', findings: [], evidenceHash: `0x${'c'.repeat(64)}`, source: 'LIVE' };
  const evidence = preparedClosureEvidence(current.closure);
  const docs = { 'report.json': { ...result, scope: 'RESTRICTED_NODE_DOCKER_V2_1' },
    'prepared/source-identity.json': sourceIdentity, 'prepared/baseline.json': baselineDocument, 'static/package-diff.json': comparison,
    'prepared/binding.json': binding, 'runtime/descriptor.json': binding.descriptor, 'runtime/execution-policy.json': binding.executionPolicy, 'runtime/tools.json': tools,
    'prepared/observation.json': { source: 'LIVE_DOCKER', identity: { observedDescriptorDigest: binding.descriptorDigest, sourceArtifactDigest: binding.sourceArtifactDigest,
      executionPolicyDigest: binding.executionPolicyDigest, finalImageDigest: binding.finalImageDigest,
      preparationDescriptorDigest: hashPreparedRuntimeDescriptor({ ...binding.descriptor, toolSurfaceHash: null }) },
      steps: { discovery: stage(), normal: stage('NORMAL'), adversarial: stage('ADVERSARIAL') }, issues: [],
      scenarios: semantic.reviews.probe.report.scenarios, generation: { ...semantic.reviews.probe.execution, status: 'SCOPED_GENERATED_VALIDATED' } },
    'static/closure-inventory.json': evidence.inventory, 'static/closure-source.json': evidence.source, 'static/closure-report.json': evidence.report,
    'static/sbom.json': evidence.sbom, 'static/findings.json': evidence.findings, 'semantic/reviews.json': semantic };
  return { docs, result, binding, trusted, context };
}

test('independent prepared baseline ID rejects a valid same-source/image policy rebinding', () => {
  const current = boundFixture('const count=2;', 'current', scopedBaselineReviewPolicy('LOCAL_CONTRACT_TEST'));
  const before = boundFixture('const count=1;', 'before', scopedReviewPolicy('LOCAL_CONTRACT_TEST'));
  const context = { sourceIdentity: current.selection.sourceIdentity, executionPolicy: current.selection.binding.executionPolicy, baseline: before.selection };
  assert.doesNotThrow(() => checkedScopedBaselineAuthority(context, before.trusted));
  for (const semantic of [scopedReviewPolicy('LOCAL_CONTRACT_TEST'), scopedBaselineReviewPolicy('LOCAL_CONTRACT_TEST')]) {
    const binding = createPreparedReleaseBinding({ sourceReleaseId: before.selection.sourceIdentity.releaseId,
      descriptor: before.selection.binding.descriptor, executionPolicy: scopedPreparedExecutionPolicy({
        collectorDigest: digest, observerDigest: digest, egressAllowHosts: ['other-mail.local'] }, semantic) });
    const releaseId = exactReleaseIdentity({ toolId: before.selection.sourceIdentity.toolId, ...binding }).releaseId;
    assert.notEqual(releaseId, before.selection.releaseId);
    assert.equal(binding.finalImageDigest, before.selection.binding.finalImageDigest);
    const changed = { ...context, baseline: { ...before.selection, binding, releaseId } };
    assert.throws(() => checkedScopedBaselineAuthority(changed, before.trusted), /SCOPED_BASELINE_AUTHORITY_MISMATCH/);
    assert.doesNotThrow(() => checkedScopedBaselineAuthority(changed, { ...before.trusted, releaseId }), 'separately selected new ID may be compared');
  }
});

test('2.1 aggregate recomputes actual before/after bytes, authority, diff, shared DTO and executed calls', async context => {
  const { ai } = await provider(context);
  for (const before of ['const count=1;', null]) {
    const original = await contractEvidence(ai, before), { docs, result, binding, trusted } = original;
    const assess = (documents = docs, authority = trusted) => assessScopedPreparedPolicyV21(createEvidenceBundle(documents), result, binding, authority);
    assert.equal(assess().verdict, 'PASS', JSON.stringify(assess()));
    assert.equal(assessScopedPreparedPolicy(createEvidenceBundle(docs), result, binding, trusted).verdict, 'ABSTAIN');
    for (const mutate of [
      d => d['static/package-diff.json'].dependencies.push({ name: 'unmeasured', before: null, after: '1.0.0' }),
      d => d['semantic/reviews.json'].input.packageDiff.currentClosureDigest = digest,
      d => d['semantic/reviews.json'].proof.inputDigest = digest,
      d => delete d['semantic/reviews.json'].reviews.critic,
      d => d['prepared/source-identity.json'].manifestDigest = digest,
      d => d['static/closure-source.json'].files[0].base64 = Buffer.from('{}').toString('base64'),
      d => d['prepared/observation.json'].steps.normal.callResults[0].argumentsDigest = digest,
    ]) {
      const changed = structuredClone(docs); mutate(changed);
      assert.equal(assess(changed).verdict, 'ABSTAIN', String(mutate));
    }
    assert.equal(assess(docs, { ...trusted, sourceIdentity: undefined }).verdict, 'ABSTAIN');
    assert.equal(assess(docs, { ...trusted, baseline: undefined }).verdict, 'ABSTAIN');
    if (before === null) continue;
    for (const mutate of [
      d => d['prepared/baseline.json'].closure.source.files[0].base64 = Buffer.from('{}').toString('base64'),
      d => d['prepared/baseline.json'].tools[0].description = 'unmeasured',
      d => d['prepared/baseline.json'].discovery.runtimeIdentity.imageDigest = digest,
      d => d['prepared/baseline.json'].discovery.timedOut = true,
      d => d['prepared/baseline.json'].discovery.callResults.push({ name: 'list_messages' }),
      d => d['prepared/baseline.json'].discovery.canaryExfiltration = true,
      d => d['prepared/baseline.json'].selection.releaseId = `0x${'a'.repeat(64)}`,
      d => d['prepared/baseline.json'].publisher = { verification: { verified: true } },
    ]) {
      const changed = structuredClone(docs); mutate(changed);
      assert.equal(assess(changed).verdict, 'ABSTAIN', String(mutate));
    }
    for (const mutate of [
      t => t.baseline.sourceProvenance.authority = 'WITHDRAWN',
      t => t.baseline.sourceBudget.sourceArtifactDigest = digest,
      t => t.baseline.closureDigest = digest,
      t => delete t.baseline.releaseId,
      t => t.baseline.releaseId = t.baseline.sourceIdentity.releaseId,
      t => t.baseline.publisher = { manifest: {}, verification: { type: 'DEMO_PUBLISHER_SIGNATURE_VALID', verified: true } },
    ]) {
      const changed = structuredClone(trusted); mutate(changed);
      assert.equal(assess(docs, changed).verdict, 'ABSTAIN', String(mutate));
    }
    const later = structuredClone(docs); later['prepared/baseline.json'].observedAt = '2026-10-02T00:00:00.000Z';
    assert.equal(assess(later).verdict, 'PASS', 'observation time is evidence, not equality/identity');
  }
});

test('old static risk can escalate review tier but cannot manufacture a current deterministic FAIL', async context => {
  const { ai } = await provider(context), { docs, result, binding, trusted } = await contractEvidence(ai, 'eval("authored fixture only"); readFileSync("/work/.env");');
  assert.equal(docs['prepared/baseline.json'].closure.findings[0].code, 'SENSITIVE_FILE_READ');
  assert.equal(docs['semantic/reviews.json'].input.tier, 3);
  assert.equal(assessScopedPreparedPolicyV21(createEvidenceBundle(docs), result, binding, trusted).verdict, 'PASS');
  const changedResult = { ...result, scanStatus: 'FAILED', findings: [{ code: 'CANARY_EXFILTRATION', deterministic: true, severity: 'CRITICAL',
    stage: 'SANDBOX', message: 'Synthetic observed current failure', evidence: { canaryHash: 'a'.repeat(64) } }] };
  docs['report.json'] = { ...docs['report.json'], ...changedResult };
  Object.assign(docs['prepared/observation.json'].steps.discovery, { canaryExfiltration: true, canaryHash: 'a'.repeat(64) });
  assert.equal(assessScopedPreparedPolicyV21(createEvidenceBundle(docs), changedResult, binding, trusted).verdict, 'FAIL');
  assert.equal(assessScopedPreparedPolicyV21(createEvidenceBundle(docs), changedResult, binding, { ...trusted, baseline: null }).verdict, 'ABSTAIN');
});

test('dependency names/versions and script hashes share provider DTO disclosure, citations and budget', async context => {
  const { ai, requests } = await provider(context), original = input();
  original.comparison.dependencies = [{ name: 'dependency', before: '1.0.0', after: '1.1.0' }];
  original.comparison.installScripts = [{ name: 'postinstall', beforeHash: null, afterHash: sha('synthetic script never sent') }];
  original.comparison.installedDependencies = [{ path: 'node_modules/dependency', before: null,
    after: { name: 'dependency', version: '1.1.0', packageJsonDigest: digest, installedContentDigest: digest } }];
  const reviewed = await reviewScopedSemanticsV21({ ...original, ai });
  assert.equal(reviewed.scopeComplete, true, JSON.stringify(reviewed.issues));
  assert.equal(reviewed.input.packageDiff.installedDependencies[0].path, undefined);
  assert.match(reviewed.input.packageDiff.installedDependencies[0].packageId, /^sha256:/);
  for (const request of requests) {
    const dto = JSON.parse(request.input[0].content.split('\n').at(-1));
    assert.ok(dto.citations.some(span => span.source === 'packageDiff.dependencies.0.after'));
    assert.equal(request.input[0].content.includes('synthetic script never sent'), false);
  }
  requests.length = 0;
  for (const mutate of [
    v => v.comparison.dependencies[0].after = v.files[0].content,
    v => v.comparison.installScripts[0].script = 'private raw script',
    v => v.comparison.extra = 'unsupported',
    v => v.comparison.dependencies = Array.from({ length: 513 }, () => ({ name: 'dependency', before: null, after: '1' })),
  ]) {
    const changed = structuredClone(original); mutate(changed);
    await assert.rejects(reviewScopedSemanticsV21({ ...changed, ai }), /SCOPED_COMPARISON_INVALID/);
  }
  const leak = input(); leak.files[0].content = 'const customerData = "synthetic only";';
  leak.comparison.dependencies = [{ name: 'dependency', before: null, after: leak.files[0].content }];
  const denied = await reviewScopedSemanticsV21({ ...leak, ai });
  assert.equal(denied.scopeComplete, false); assert.ok(denied.issues.includes('SCOPED_DISCLOSURE_UNION_EXCEEDED'));
  assert.equal(requests.length, 0);
});

const nativeDocuments = (version, malicious = false) => {
  const pkg = { name: 'scoped-synthetic', version, bin: 'server.js', private: true, engines: { node: '>=22.14.0' }, license: 'UNLICENSED' };
  return { 'package.json': JSON.stringify(pkg),
    'package-lock.json': JSON.stringify({ name: pkg.name, version, lockfileVersion: 3, packages: { '': pkg } }),
    'server.js': authoredMailbox(tools, malicious).replace("subject:'Welcome'", `subject:'Welcome ${version}'`) };
};

test('natural safe update fits disclosure bounds; malicious and tiny over-disclosure send zero HTTP without padding', async context => {
  const { ai, requests } = await provider(context);
  const original = input(), files = value => Object.entries(value).map(([path, content]) => ({ path, content }));
  original.files = files(nativeDocuments('1.0.1')); original.baseline.files = files(nativeDocuments('1.0.0'));
  const selected = buildScopedSemanticInputV21(original);
  assert.equal(selected.proof.scopeComplete, true, JSON.stringify(selected.proof));
  const malicious = { ...original, files: files(nativeDocuments('1.0.2', true)) };
  const risky = buildScopedSemanticInputV21(malicious);
  assert.equal(risky.proof.scopeComplete, false);
  assert.ok(risky.proof.issues.includes('SCOPED_DISCLOSURE_UNION_EXCEEDED'));
  assert.ok(risky.input.excerpts.some(item => item.path.startsWith('after/') && item.content.includes('MCP_CANARY_PATH')));
  assert.equal((await reviewScopedSemanticsV21({ ...malicious, ai })).scopeComplete, false);
  assert.equal(requests.length, 0, 'native deterministic effects never authorize over-budget source disclosure');
  const small = structuredClone(original);
  for (const list of [small.files, small.baseline.files]) {
    const pkg = list.find(f => f.path === 'package.json'); const value = JSON.parse(pkg.content);
    delete value.engines; delete value.license; pkg.content = JSON.stringify(value);
  }
  const limited = buildScopedSemanticInputV21(small);
  assert.equal(limited.proof.scopeComplete, false);
  assert.ok(limited.proof.issues.includes('SCOPED_DISCLOSURE_UNION_EXCEEDED'), 'small files receive no privacy exemption');
  assert.equal((await reviewScopedSemanticsV21({ ...small, ai })).scopeComplete, false);
  assert.equal(requests.length, 0);
});

test('native Docker 2.1 binds one baseline to safe update PASS, actual canary update FAIL and exact authority (local model contract only)', {
  skip: process.env.MCPSHIELD_DOCKER_TESTS !== '1' || !process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE,
  timeout: 300_000,
}, async context => {
  const { ai, requests } = await provider(context), builderImageDigest = process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE;
  const roots = [], outputs = [];
  try {
    let previous = null, previousTrust = null;
    for (const [version, malicious] of [['1.0.0', false], ['1.0.1', false], ['1.0.2', true]]) {
      const root = await mkdtemp(join(tmpdir(), 'mcpshield-baseline-native-')); roots.push(root);
      const documents = nativeDocuments(version, malicious);
      for (const [path, content] of Object.entries(documents)) await writeFile(join(root, path), content);
      const sourceTreeDigest = await artifactDigest(root), sourceIdentity = identity('scoped-synthetic', sourceTreeDigest);
      const sourceProvenance = provenance(sourceTreeDigest), trust = readTrustedPreparedIdentity(builderImageDigest);
      const executionPolicy = scopedPreparedExecutionPolicy({ collectorDigest: trust.collectorDigest, observerDigest: trust.observerDigest,
        egressAllowHosts: ['mail-api.local', 'exfil-sink.local'] }, version === '1.0.0' ? scopedReviewPolicy('LOCAL_CONTRACT_TEST') : scopedBaselineReviewPolicy('LOCAL_CONTRACT_TEST'));
      const scopedReview = { executionPolicy, sourceProvenance, ...(previous ? { sourceIdentity, baseline: previous } : {}) };
      const trusted = { ...trust, sourceProvenance, ...(previous ? { sourceIdentity, baseline: previousTrust } : {}) };
      const callsBefore = requests.length;
      const output = await prepareAndScanRuntime({ preparation: { root, sourceDigest: sourceTreeDigest, sourceTreeDigest, builderImageDigest,
        platform: { os: 'linux', architecture: 'amd64' } }, sourceReleaseId: sourceIdentity.releaseId, releaseId: `scoped-synthetic@${version}`,
        trusted, scopedReview, ai: malicious ? undefined : ai }, { download: async () => { throw Error('NO_EXTERNAL_PACKAGE_DOWNLOADS'); } });
      outputs.push(output);
      assert.equal(output.analysis.verdict, malicious ? 'FAIL' : 'PASS', JSON.stringify(output.analysis));
      const independent = { ...await readTrustedPreparedRuntime({ descriptor: output.binding.descriptor,
        expectedDescriptorDigest: output.binding.descriptorDigest, builderImageDigest }), sourceIdentity, sourceProvenance,
        releaseId: exactReleaseIdentity({ toolId: sourceIdentity.toolId, ...output.binding }).releaseId,
        sourceBudget: { sourceArtifactDigest: sourceTreeDigest, sourceBytes: Object.values(documents).reduce((sum, s) => sum + Buffer.byteLength(s), 0) }, publisher: null };
      if (previous) {
        const authority = { ...independent, baseline: previousTrust };
        const assess = (bundle = output.bundle, result = output.result, trusted = authority) =>
          assessScopedPreparedPolicyV21(bundle, result, output.binding, trusted);
        assert.equal(assess().verdict, malicious ? 'FAIL' : 'PASS');
        const proof = JSON.parse(output.bundle.files['prepared/baseline.json']);
        assert.equal(proof.closure.inventory.source, 'LIVE_DOCKER_IMAGE_EXPORT');
        assert.equal(proof.discovery.toolSurfaceHash, previous.binding.toolSurfaceHash);
        assert.equal(proof.selection.releaseId, previousTrust.releaseId, 'safe and malicious update use the same original baseline');
        assert.equal(proof.discovery.canaryExfiltration, false, 'baseline is not the source of a current violation');
        for (const trusted of [
          { ...authority, sourceIdentity: { ...sourceIdentity, manifestDigest: digest } },
          { ...authority, baseline: { ...previousTrust, releaseId: sourceIdentity.releaseId } },
          { ...authority, baseline: { ...previousTrust, sourceProvenance: { ...previousTrust.sourceProvenance, authority: 'WITHDRAWN' } } },
        ]) assert.equal(assess(output.bundle, output.result, trusted).verdict, 'ABSTAIN', 'even real effects cannot substitute selected authority');
        if (malicious) {
          assert.equal(requests.length, callsBefore, 'canary FAIL is measured by the independent sink, not an AI decision');
          assert.equal(output.result.scanStatus, 'FAILED');
          const observation = JSON.parse(output.bundle.files['prepared/observation.json']);
          const step = observation.steps.discovery, actualHash = step.canaryHash;
          assert.equal(step.canaryExfiltration, true); assert.match(actualHash, /^[a-f0-9]{64}$/);
          const finding = output.result.findings.find(item => item.code === 'CANARY_EXFILTRATION' && item.deterministic && item.stage === 'SANDBOX');
          assert.equal(finding?.evidence.canaryHash, actualHash, 'current independently observed canary commits the FAIL');
          const tampered = structuredClone(output.result), forgedHash = sha('not the observed native canary').slice(7);
          assert.notEqual(actualHash, forgedHash);
          tampered.findings.find(item => item.code === 'CANARY_EXFILTRATION').evidence.canaryHash = forgedHash;
          const docs = Object.fromEntries(Object.entries(output.bundle.files).map(([path, content]) => [path, JSON.parse(content)]));
          docs['report.json'] = { ...docs['report.json'], ...tampered };
          assert.equal(assess(createEvidenceBundle(docs), tampered).verdict, 'ABSTAIN', 'a re-Merkled fabricated canary hash cannot FAIL');
        } else {
          const again = await scanPreparedRuntime({ descriptor: output.binding.descriptor, expectedDescriptorDigest: output.binding.descriptorDigest,
            sourceReleaseId: sourceIdentity.releaseId, releaseId: `scoped-synthetic@${version}`, trusted: authority, scopedReview, ai });
          assert.equal(again.analysis.verdict, 'PASS', JSON.stringify(again.analysis));
          assert.deepEqual(again.binding, output.binding); assert.notEqual(again.result.scanId, output.result.scanId);
          assert.deepEqual(JSON.parse(again.bundle.files['static/package-diff.json']), JSON.parse(output.bundle.files['static/package-diff.json']));
        }
        await assert.rejects(scanPreparedRuntime({ descriptor: output.binding.descriptor, expectedDescriptorDigest: output.binding.descriptorDigest,
          sourceReleaseId: sourceIdentity.releaseId, releaseId: `scoped-synthetic@${version}`, trusted: { ...independent, baseline: null }, scopedReview, ai }),
        /SCOPED_BASELINE_AUTHORITY_MISMATCH/);
      }
      if (previous === null) {
        previous = { releaseId: exactReleaseIdentity({ toolId: sourceIdentity.toolId, ...output.binding }).releaseId,
          sourceIdentity, binding: output.binding, sourceProvenance };
        previousTrust = independent;
      }
    }
  } finally {
    for (const output of outputs.reverse()) await output?.cleanup?.();
    for (const root of roots) await removeFixtureSnapshot(root);
  }
});
