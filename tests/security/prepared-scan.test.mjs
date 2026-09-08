import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import { closureManifest } from '../../services/resolver/src/closure-files.mjs';
import { hashPreparedRuntimeDescriptor } from '../../services/resolver/src/runtime-descriptor.mjs';
import { createPreparedReleaseBinding, preparedExecutionPolicy } from '../../services/scanner/src/prepared-binding.mjs';
import { inspectPreparedSources, reviewPreparedSemantics } from '../../services/scanner/src/prepared-review.mjs';
import { assessPreparedPolicy } from '../../services/scanner/src/prepared-policy.mjs';
import { canonicalJson, createEvidenceBundle } from '../../services/scanner/src/evidence.mjs';
import { toolSurfaceHash } from '../../services/scanner/src/tool-surface.mjs';

const sha = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const digest = sha('synthetic-test-identity');
const clean = { riskClaims: [], semanticDiff: { purposeChanged: false, dataScopeExpanded: false, newHiddenObligation: false }, needsHumanReview: false };
const tools = [{ name: 'list_messages', inputSchema: { type: 'object', properties: {}, additionalProperties: false } }];

async function provider(run) {
  const requests = [];
  const server = createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    requests.push(JSON.parse(Buffer.concat(chunks)));
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(clean));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try { await run({ requests, ai: { allowRemoteAi: true, provider: 'custom', disclosurePolicy: 'LOCAL_CONTRACT_TEST', url: `http://127.0.0.1:${server.address().port}`, timeoutMs: 1000 } }); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

function syntheticClosure() {
  const pkg = { name: 'synthetic', version: '1.0.0', bin: 'server.js' };
  const documents = { 'package.json': JSON.stringify(pkg), 'server.js': "require('fixture'); // no host execution",
    'package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': pkg, 'node_modules/fixture': { version: '1.0.0' } } }),
    'node_modules/fixture/package.json': JSON.stringify({ name: 'fixture', version: '1.0.0' }),
    'node_modules/fixture/index.js': 'module.exports=1;' };
  const contents = Object.entries(documents).map(([path, text]) => ({ path, bytes: Buffer.from(text) }));
  const entries = contents.map(({ path, bytes }) => ({ path, type: 'File', mode: 0o444, digest: sha(bytes) }));
  const manifest = closureManifest(entries);
  return { ...manifest, contents, bytes: contents.reduce((total, { bytes }) => total + bytes.length, 0), source: 'LIVE_DOCKER_IMAGE_EXPORT' };
}

test('full installed source review includes dependency bytes, independent blind critic and exact redacted coverage', async () => provider(async ({ requests, ai }) => {
  const reviewed = inspectPreparedSources(syntheticClosure());
  assert.equal(reviewed.inventory.staticComplete, true);
  assert.equal(reviewed.sbom.complete, true);
  assert.equal(reviewed.sbom.components.length, 2);
  const semantic = await reviewPreparedSemantics({ files: reviewed.files, tools, releaseId: 'synthetic@1.0.0', ai });
  assert.equal(semantic.complete, true);
  assert.equal(semantic.independentCriticComplete, true);
  assert.equal(semantic.noUnresolvedRisk, true);
  assert.equal(semantic.disclosure.policy, 'LOCAL_CONTRACT_TEST');
  assert.equal(semantic.disclosure.providerQuality, 'PROVIDER_QUALITY_NOT_MEASURED');
  assert.equal(requests.length, 2);
  assert.match(requests[1].prompt, /independent adversarial reviewer/);
  assert.match(requests[0].prompt, /node_modules\/fixture\/index.js/);
  assert.equal(requests[0].prompt.includes('riskClaims":[]'), false);
  const partial = await reviewPreparedSemantics({ files: [{ path: 'large.js', content: 'x'.repeat(100000) }], tools, releaseId: 'synthetic@1.0.0', ai: { ...ai, maxBatches: 1 } });
  assert.equal(partial.complete, false);
  assert.ok(partial.issues.includes('PREPARED_AI_COVERAGE_BUDGET_EXCEEDED'));
  assert.equal((await reviewPreparedSemantics({ files: reviewed.files, tools, releaseId: 'synthetic@1.0.0' })).complete, false);
}));

// Deliberately synthetic contract evidence, not an assertion of actual Docker execution.
test('independent prepared policy rejects forged source/raw hashes, omitted critic, wrong image anchors and tool substitution', async () => provider(async ({ ai }) => {
  const closure = syntheticClosure();
  const reviewed = inspectPreparedSources(closure);
  const semantic = await reviewPreparedSemantics({ files: reviewed.files, tools, releaseId: 'synthetic@1.0.0', ai });
  const descriptor = { schemaVersion: 'mcpshield.prepared-runtime.v1', stage: 'CLOSURE_PREPARED', profile: 'npm-closure-v1',
    sourceDigest: digest, sourceTreeDigest: digest, lockDigest: digest, lockOrigin: 'SUPPLIED', builderImageDigest: digest,
    platform: { os: 'linux', architecture: 'amd64' }, finalImageDigest: digest, toolSurfaceHash: toolSurfaceHash(tools),
    entrypoint: { path: 'server.js', digest: sha(closure.contents.find(({ path }) => path === 'server.js').bytes) },
    argv: ['/usr/local/bin/node', '/app/server.js'], policy: { acquisitionNetwork: 'REGISTRY_ONLY_SEPARATE', installNetwork: 'NONE',
      installScripts: 'DISABLED', executionNetwork: 'INTERNAL_SYNTHETIC_PROXY', user: 'NON_ROOT', rootFilesystem: 'READ_ONLY' } };
  const executionPolicy = preparedExecutionPolicy({ collectorDigest: digest, observerDigest: digest, egressAllowHosts: [] });
  const binding = createPreparedReleaseBinding({ sourceReleaseId: `0x${'a'.repeat(64)}`, descriptor, executionPolicy });
  const original = { ...descriptor, stage: 'PREFLIGHT', finalImageDigest: null, toolSurfaceHash: null };
  const trusted = { builderImageDigest: digest, collectorDigest: digest, observerDigest: digest, finalImageDigest: digest,
    platform: descriptor.platform, closureDigest: closure.digest, entrypointDigest: descriptor.entrypoint.digest, sourceDescriptorDigest: hashPreparedRuntimeDescriptor(original) };
  const runtime = { imageDigest: digest, platform: descriptor.platform, argv: descriptor.argv };
  const step = { protocolComplete: true, timedOut: false, exitCode: 0, failureCode: null, pages: 1,
    permissionProfile: 'NODE_PERMISSION_READ_ONLY_V1', runtimeIdentity: runtime, toolSurfaceHash: descriptor.toolSurfaceHash,
    egressEvents: [], canaryExfiltration: false, callResults: [{ name: 'list_messages', isError: false, contentHash: 'b'.repeat(64) }] };
  const result = { schemaVersion: '1.0.0', scanId: randomUUID(), releaseId: 'synthetic@1.0.0', artifactDigest: binding.artifactDigest,
    toolSurfaceHash: binding.toolSurfaceHash, scanStatus: 'PASSED', findings: [], evidenceHash: `0x${'c'.repeat(64)}`, source: 'LIVE' };
  const docs = { 'report.json': { ...result, scope: 'RESTRICTED_NODE_DOCKER_V1' }, 'prepared/binding.json': binding,
    'runtime/descriptor.json': descriptor, 'runtime/execution-policy.json': executionPolicy, 'runtime/tools.json': tools,
    'prepared/observation.json': { source: 'LIVE_DOCKER', identity: { observedDescriptorDigest: binding.descriptorDigest,
      sourceArtifactDigest: binding.sourceArtifactDigest, executionPolicyDigest: binding.executionPolicyDigest, finalImageDigest: digest,
      preparationDescriptorDigest: hashPreparedRuntimeDescriptor({ ...descriptor, toolSurfaceHash: null }) },
      steps: { discovery: { ...step, callResults: [] }, normal: step, adversarial: step }, issues: [],
      scenarios: ['NORMAL', 'ADVERSARIAL'].map((kind) => ({ kind, toolCall: { name: 'list_messages' } })) },
    'static/closure-inventory.json': { ...reviewed.inventory, source: closure.source },
    'static/closure-report.json': { ...closureManifest(closure.entries), bytes: closure.bytes,
      sourceDescriptorDigest: hashPreparedRuntimeDescriptor(original), installScripts: false, installNetwork: 'NONE' },
    'static/closure-source.json': { complete: true, files: closure.contents.map(({ path, bytes }) => ({ path, base64: bytes.toString('base64') })) },
    'static/findings.json': [], 'static/sbom.json': reviewed.sbom, 'semantic/reviews.json': semantic };
  const assessed = assessPreparedPolicy(createEvidenceBundle(docs), result, binding, trusted);
  assert.equal(assessed.verdict, 'PASS', JSON.stringify(assessed));
  for (const mutate of [(d) => d['runtime/tools.json'][0].description = 'new raw surface',
    (d) => delete d['semantic/reviews.json'].disclosure,
    (d) => delete d['semantic/reviews.json'].reviews[0].critic.execution.disclosure,
    (d) => delete d['semantic/reviews.json'].reviews[0].critic,
    (d) => d['static/closure-source.json'].files.find(({ path }) => path === 'server.js').base64 = Buffer.from('forged benign bytes').toString('base64'),
    (d) => d['semantic/reviews.json'].reviews[0].input.excerpts[0].content = 'forged benign text',
    (d) => d['static/closure-inventory.json'].digest = digest,
    (d) => d['prepared/observation.json'].steps.normal.callResults = []]) {
    const changed = structuredClone(docs); mutate(changed);
    assert.equal(assessPreparedPolicy(createEvidenceBundle(changed), result, binding, trusted).verdict, 'ABSTAIN');
  }
  for (const field of Object.keys(trusted)) {
    assert.equal(assessPreparedPolicy(createEvidenceBundle(docs), result, binding, { ...trusted, [field]: null }).verdict, 'ABSTAIN', field);
  }
  assert.equal(assessPreparedPolicy(createEvidenceBundle(docs), result, binding).verdict, 'ABSTAIN');
}));

test('full-source privacy fence rejects external analyzer or critic before either request, and requires explicit local contract declaration', async () => provider(async ({ requests, ai }) => {
  for (const profile of ['restricted-node-docker-v1', 'restricted-oci-offline-v1']) {
    for (const config of [{ ...ai, disclosurePolicy: undefined }, { ...ai, url: 'https://example.invalid/model' },
      { ...ai, provider: 'openai' }, { ...ai, url: 'http://localhost:12345' },
      { ...ai, critic: { url: 'https://example.invalid/critic' } },
      { ...ai, critic: { disclosurePolicy: undefined } }, { ...ai, critic: { provider: 'openai' } }]) {
      const result = await reviewPreparedSemantics({ files: [{ path: 'synthetic.js', content: 'NOT_FOR_EXTERNAL_DISCLOSURE' }],
        tools, releaseId: 'synthetic@1.0.0', profile, ai: config });
      assert.equal(result.complete, false);
      assert.equal(result.noUnresolvedRisk, false);
      assert.equal(result.disclosure.policy, 'FULL_SOURCE_REMOTE_FORBIDDEN');
      assert.ok(result.issues.some((issue) => issue.endsWith('_FULL_SOURCE_DISCLOSURE_FORBIDDEN')));
      assert.deepEqual(result.reviews, []);
    }
  }
  assert.equal(requests.length, 0, 'A denied critic must also prevent the analyzer from receiving source.');
}));
