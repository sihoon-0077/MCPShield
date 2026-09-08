import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { canonicalJson } from '../../services/scanner/src/evidence.mjs';
import { ociHash, hashOciRuntimeDescriptor, OCI_SOURCE_BUDGET_PROFILE, OCI_OBSERVATION_POLICY } from '../../services/resolver/src/oci-runtime-descriptor.mjs';
import { ociExecutionPolicy, validateOciExecutionPolicy, createOciReleaseBinding, validateOciReleaseBinding } from '../../services/scanner/src/oci-binding.mjs';
import { preparedSemanticPrompt, reviewPreparedSemantics } from '../../services/scanner/src/prepared-review.mjs';

const digest = ociHash('authored synthetic identity');
const sourceReleaseId = '0x' + 'a'.repeat(64), surface = '0x' + 'b'.repeat(64);
const trust = Object.fromEntries(['baseImageDigest', 'baseCatalogueDigest', 'trivyImageDigest', 'databaseDigest',
  'observerDigest', 'sinkImageDigest', 'sinkCodeDigest'].map((field) => [field, ociHash(field)]));
const descriptor = { schemaVersion: 'mcpshield.oci-runtime.v1', profile: 'oci-container-v1', stage: 'OBSERVED',
  budgetProfile: OCI_SOURCE_BUDGET_PROFILE, sourceBytes: 1000, layerArchiveBytes: 2048, exportArchiveBytes: 2048,
  sourceTreeDigest: ociHash('original source V2 tree'), sourceIndexDigest: digest, manifestDigest: digest, configDigest: digest,
  platform: { os: 'linux', architecture: 'amd64' }, finalImageDigest: digest, imageDigestKind: 'DOCKER_IMAGE_CONFIG_ID',
  rootfsDigest: digest, entrypoint: { requestedPath: '/bin/sh', resolvedPath: '/bin/busybox', contentDigest: digest, linkChainDigest: digest },
  argv: ['/bin/sh', '/server.sh'], workingDirectory: '/', environmentDigest: digest, toolSurfaceHash: surface, policy: OCI_OBSERVATION_POLICY };

test('pure OCI binding uses exact six-field manifest, preserves original source tree and cannot imply approval', () => {
  const executionPolicy = ociExecutionPolicy(trust);
  const binding = createOciReleaseBinding({ sourceReleaseId, descriptor, executionPolicy });
  assert.equal(validateOciReleaseBinding(binding), true);
  assert.equal(binding.profile, 'oci-container-v1');
  assert.equal(binding.artifactDigest, hashOciRuntimeDescriptor(descriptor));
  assert.equal(binding.sourceArtifactDigest, descriptor.sourceTreeDigest);
  assert.notEqual(binding.sourceArtifactDigest, binding.artifactDigest);
  const { schemaVersion, profile, sourceArtifactDigest, descriptorDigest, executionPolicyDigest } = binding;
  assert.equal(binding.manifestDigest, ociHash(canonicalJson({ schemaVersion, profile, sourceReleaseId, sourceArtifactDigest, descriptorDigest, executionPolicyDigest })));
  assert.equal(binding.approvalVerdict, undefined); assert.equal(binding.ready, undefined);
  for (const field of Object.keys(binding)) assert.equal(validateOciReleaseBinding({ ...binding, [field]: null }), false, field);
  assert.equal(validateOciReleaseBinding({ ...binding, hostPath: '/arbitrary' }), false);
  for (const field of Object.keys(trust)) {
    const altered = ociExecutionPolicy({ ...trust, [field]: digest });
    assert.notEqual(createOciReleaseBinding({ sourceReleaseId, descriptor, executionPolicy: altered }).manifestDigest, binding.manifestDigest, field);
    assert.equal(validateOciExecutionPolicy({ ...executionPolicy, trust: { ...trust, [field]: 'mutable:tag' } }), false);
  }
  assert.throws(() => createOciReleaseBinding({ sourceReleaseId, descriptor: { ...descriptor, stage: 'IMPORTED', toolSurfaceHash: null }, executionPolicy }), /DISCOVERED/);
  const unchanged = structuredClone(binding); descriptor.argv.push('synthetic-change');
  assert.deepEqual(binding, unchanged); descriptor.argv.pop();
});

test('OCI execution commitment rejects privilege/network/host-data expansion and retains explicit unobserved filesystem/native limitations', () => {
  const policy = ociExecutionPolicy(trust);
  assert.equal(policy.gateway.network, 'NONE'); assert.equal(policy.gateway.hostMounts, 'NONE');
  assert.equal(policy.review.filesystem, 'STATIC_IMAGE_INVENTORY_NOT_SYSCALL_TRACE');
  assert.equal(policy.review.unknownBinary, 'ABSTAIN');
  for (const mutate of [(p) => p.gateway.network = 'HOST', (p) => p.gateway.hostMounts = ['/private'],
    (p) => p.isolation.user = '0:0', (p) => p.isolation.seccomp = 'UNCONFINED',
    (p) => p.gateway.fixedEnvironment.NODE_OPTIONS = '--require=/private', (p) => p.review.unknownBinary = 'ASSUME_SAFE',
    (p) => p.observation.egressAllowHosts.push('external.example'), (p) => p.extra = true]) {
    const changed = structuredClone(policy); mutate(changed); assert.equal(validateOciExecutionPolicy(changed), false);
  }
  assert.throws(() => ociExecutionPolicy({ ...trust, hostPath: '/not-allowed' }), /POLICY_INVALID/);
});

test('semantic engine keeps the default Node prompt unchanged and rejects invented or ambiguous OCI profiles', async () => {
  const candidate = { releaseId: 'synthetic@1.0.0', tools: [], baselineTools: [], excerpts: [] };
  assert.equal(preparedSemanticPrompt(candidate, 'analyzer'), preparedSemanticPrompt(candidate, 'analyzer', 'restricted-node-docker-v1'));
  assert.match(preparedSemanticPrompt(candidate, 'analyzer'), /child processes, workers, native addons and dynamic string code generation are unsupported/);
  const oci = preparedSemanticPrompt(candidate, 'analyzer', 'restricted-oci-offline-v1');
  assert.match(oci, /Node-only permission assumptions do not apply/);
  assert.match(oci, /Static image inventory is not filesystem syscall observation/);
  assert.doesNotMatch(oci, /child processes, workers, native addons and dynamic string code generation are unsupported/);
  assert.throws(() => preparedSemanticPrompt(candidate, 'critic', 'arbitrary-policy'), /PROFILE_INVALID/);
  const noAi = await reviewPreparedSemantics({ files: [], tools: [], releaseId: 'synthetic@1.0.0', profile: 'restricted-oci-offline-v1' });
  assert.equal(noAi.complete, false); assert.deepEqual(noAi.issues, ['OCI_EXPLICIT_AI_AND_CRITIC_REQUIRED']);
  for (const files of [[{ path: 'same', content: '' }, { path: 'same', content: '' }], [{ path: 'MCP_TOOLS_COMPLETE.json', content: 'spoof' }]]) {
    await assert.rejects(() => reviewPreparedSemantics({ files, tools: [], releaseId: 'synthetic@1.0.0', profile: 'restricted-oci-offline-v1' }), /SOURCES_INVALID/);
  }
});

test('OCI analyzer and blind critic use exact existing citations/coverage but separate profile/schema provenance (local HTTP contract only)', async () => {
  const requests = [], clean = { riskClaims: [], semanticDiff: { purposeChanged: false, dataScopeExpanded: false, newHiddenObligation: false }, needsHumanReview: false };
  const server = createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    requests.push(JSON.parse(Buffer.concat(chunks)));
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(clean));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const content = 'print("authored inert Python source")\n';
    const review = await reviewPreparedSemantics({ files: [{ path: 'server.py', rawDigest: ociHash(content), content }],
      tools: [{ name: 'synthetic', inputSchema: { type: 'object' } }], releaseId: 'synthetic@1.0.0', profile: 'restricted-oci-offline-v1',
      ai: { allowRemoteAi: true, provider: 'custom', url: `http://127.0.0.1:${server.address().port}`, timeoutMs: 1000 } });
    assert.equal(review.complete, true); assert.equal(review.independentCriticComplete, true);
    assert.equal(review.semanticProfile, 'restricted-oci-offline-v1');
    assert.equal(requests.length, 2);
    for (const role of ['analyzer', 'critic']) assert.equal(review.reviews[0][role].execution.schemaName, `mcpshield_oci_${role}`);
    assert.equal(review.reviews[0].input.excerpts.find(({ path }) => path === 'server.py').content, content);
    assert.match(requests[1].prompt, /independent adversarial reviewer/);
    assert.equal(requests[1].prompt.includes('riskClaims":[]'), false);
  } finally { await new Promise((resolve) => server.close(resolve)); }
});
