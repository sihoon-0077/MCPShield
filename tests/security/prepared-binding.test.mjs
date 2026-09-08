import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { createPreparedReleaseBinding, validatePreparedReleaseBinding, preparedExecutionPolicy,
  validatePreparedExecutionPolicy } from '../../services/scanner/src/prepared-binding.mjs';
import { canonicalJson } from '../../services/scanner/src/evidence.mjs';
import { hashPreparedRuntimeDescriptor } from '../../services/resolver/src/runtime-descriptor.mjs';

const sha = `sha256:${'a'.repeat(64)}`;
const descriptor = { schemaVersion: 'mcpshield.prepared-runtime.v1', stage: 'CLOSURE_PREPARED', profile: 'npm-closure-v1',
  sourceDigest: sha, sourceTreeDigest: sha, lockDigest: sha, lockOrigin: 'SUPPLIED', builderImageDigest: sha,
  platform: { os: 'linux', architecture: 'amd64' }, finalImageDigest: sha, toolSurfaceHash: `0x${'b'.repeat(64)}`,
  entrypoint: { path: 'server.js', digest: sha }, argv: ['/usr/local/bin/node', '/app/server.js'],
  policy: { acquisitionNetwork: 'REGISTRY_ONLY_SEPARATE', installNetwork: 'NONE', installScripts: 'DISABLED',
    executionNetwork: 'INTERNAL_SYNTHETIC_PROXY', user: 'NON_ROOT', rootFilesystem: 'READ_ONLY' } };

test('prepared binding commits exactly six manifest fields and detects every execution/identity substitution', () => {
  const executionPolicy = preparedExecutionPolicy({ collectorDigest: sha, observerDigest: sha, egressAllowHosts: ['mail-api.local'] });
  const binding = createPreparedReleaseBinding({ sourceReleaseId: `0x${'c'.repeat(64)}`, descriptor, executionPolicy });
  assert.equal(validatePreparedReleaseBinding(binding), true);
  assert.equal(binding.artifactDigest, hashPreparedRuntimeDescriptor(descriptor));
  const { schemaVersion, profile, sourceReleaseId, sourceArtifactDigest, descriptorDigest, executionPolicyDigest } = binding;
  assert.equal(binding.manifestDigest, `sha256:${createHash('sha256').update(canonicalJson({ schemaVersion, profile,
    sourceReleaseId, sourceArtifactDigest, descriptorDigest, executionPolicyDigest })).digest('hex')}`);
  for (const field of Object.keys(binding)) {
    assert.equal(validatePreparedReleaseBinding({ ...binding, [field]: null }), false, field);
  }
  assert.equal(validatePreparedReleaseBinding({ ...binding, hostPath: '/untrusted' }), false);
  const changed = structuredClone(binding); changed.descriptor.argv[1] = '/app/other.js';
  assert.equal(validatePreparedReleaseBinding(changed), false);
  assert.throws(() => createPreparedReleaseBinding({ sourceReleaseId, descriptor: { ...descriptor, toolSurfaceHash: null }, executionPolicy }), /DISCOVERED/);
});

test('execution policy explicitly binds tighter Gateway permissions and rejects additional privileges', () => {
  const policy = preparedExecutionPolicy({ collectorDigest: sha, observerDigest: sha, egressAllowHosts: ['mail-api.local'] });
  assert.equal(validatePreparedExecutionPolicy(policy), true);
  assert.deepEqual(policy.gateway.nodeArguments, ['--permission', '--allow-fs-read=/app', '--disallow-code-generation-from-strings']);
  assert.equal(policy.gateway.network, 'NONE');
  for (const mutate of [(p) => p.gateway.nodeArguments.push('--allow-child-process'), (p) => p.gateway.network = 'HOST',
    (p) => p.nodeArguments.push('--allow-fs-read=*'), (p) => p.observerDigest = 'mutable-tag', (p) => p.extra = true]) {
    const changed = structuredClone(policy); mutate(changed); assert.equal(validatePreparedExecutionPolicy(changed), false);
  }
});
