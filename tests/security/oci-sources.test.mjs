import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { canonicalJson } from '../../services/scanner/src/evidence.mjs';
import { createOciRuntimeCatalogue } from '../../services/scanner/src/oci-coverage.mjs';
import { reconstructOciSemanticSources, verifyOciSemanticReview } from '../../services/scanner/src/oci-sources.mjs';
import { reviewPreparedSemantics } from '../../services/scanner/src/prepared-review.mjs';
import { scanOciRuntime } from '../../services/scanner/src/oci-scan.mjs';
import { ociHash, hashOciRuntimeDescriptor, OCI_OBSERVATION_POLICY, OCI_SOURCE_BUDGET_PROFILE } from '../../services/resolver/src/oci-runtime-descriptor.mjs';

const digest = ociHash('synthetic fixture identity'), platform = { os: 'linux', architecture: 'amd64' };
const entry = (path, text) => ({ path, type: 'File', mode: 0o555, uid: 0, gid: 0, link: null, digest: ociHash(text) });
function evidence() {
  const base = [entry('runner', Buffer.from([0, 1, 2, 3])), entry('removed.txt', 'removed base text')];
  const catalogue = createOciRuntimeCatalogue({ baseImageDigest: digest, platform, filesystem: { entries: base, digest: ociHash(canonicalJson(base)) } });
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

test('independent OCI semantic reconstruction rejects rewritten excerpts, missing role, changed metadata/runtime/tools and profile substitution', async () => {
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
});
