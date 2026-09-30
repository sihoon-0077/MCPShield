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
import { scopedBaselineCommitment, comparePreparedClosures } from '../../services/scanner/src/scoped-baseline.mjs';
import { assessScopedPreparedPolicy } from '../../services/scanner/src/prepared-policy.mjs';
import { scopedOciExecutionPolicy } from '../../services/scanner/src/oci-binding.mjs';
import { closureManifest } from '../../services/resolver/src/closure-files.mjs';
import { toolSurfaceHash } from '../../services/scanner/src/tool-surface.mjs';
import { exactReleaseIdentity } from '../../packages/contracts-sdk/src/v2-identity.mjs';

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
function input(code = 'fetch("https://mail-api.local/messages");') {
  const files = [{ path: 'server.js', content: padding + code + padding }], sourceArtifactDigest = sha('current source');
  return { files, tools: structuredClone(tools), executionPolicy: policy(scopedBaselineReviewPolicy('LOCAL_CONTRACT_TEST')),
    sourceArtifactDigest, sourceIdentity: identity('synthetic', sourceArtifactDigest), sourceProvenance: provenance(sourceArtifactDigest),
    runtime: { profile: 'restricted-node-docker-v2', runtimeDigest: digest, environmentDigest: digest },
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
  const first = buildScopedSemanticInputV21({ ...original, baseline: null });
  assert.equal(first.input.baseline, null); assert.equal(first.proof.baselineProvided, false);
  assert.equal(first.input.comparison, 'NO_BASELINE_NOT_AN_UPDATE_COMPARISON');
  assert.deepEqual(first.input.changes, []);
  assert.ok(first.input.excerpts.length, 'first release still reviews current risk');
});

test('identical baseline never removes current risk selection; changing before bytes is bound to proof', () => {
  const original = input(), selected = buildScopedSemanticInputV21(original);
  assert.equal(selected.proof.scopeComplete, true, JSON.stringify(selected.proof.issues));
  assert.equal(selected.proof.baselineProvided, true); assert.deepEqual(selected.input.changes, []);
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
