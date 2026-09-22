import { createHash } from 'node:crypto';
import { canonicalJson } from './evidence.mjs';
import { hashPreparedRuntimeDescriptor } from '../../resolver/src/runtime-descriptor.mjs';
import { SCOPED_NODE_PROFILE, scopedReviewPolicy, validateScopedReviewPolicy } from './scoped-policy.mjs';

const hash = (value) => `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
const sha = /^sha256:[a-f0-9]{64}$/;
const bytes32 = /^0x[a-f0-9]{64}$/;
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join(',') === [...fields].sort().join(',');

export function preparedExecutionPolicy(input) {
  if (!exact(input, ['collectorDigest', 'observerDigest', 'egressAllowHosts']) ||
    !sha.test(input.collectorDigest) || !sha.test(input.observerDigest) || !Array.isArray(input.egressAllowHosts) ||
    input.egressAllowHosts.length > 32 || input.egressAllowHosts.some((host) => typeof host !== 'string' ||
      !/^[a-z0-9][a-z0-9.-]*\.(?:local|test)$/.test(host))) throw Error('PREPARED_EXECUTION_POLICY_INVALID');
  return { profile: 'prepared-node-observation-v1', nodeArguments: ['--permission', '--allow-fs-read=/app',
    '--allow-fs-read=/observer', '--allow-fs-read=/home/test', '--require', '/observer/observer-preload.cjs'],
    collectorDigest: input.collectorDigest, observerDigest: input.observerDigest,
    egressAllowHosts: [...new Set(input.egressAllowHosts)].sort(),
    isolation: 'READ_ONLY_NON_ROOT_DOCKER_INTERNAL_NETWORK', imageDigestKind: 'DOCKER_IMAGE_CONFIG_ID',
    gateway: { profile: 'prepared-node-network-none-v1', nodeArguments: ['--permission', '--allow-fs-read=/app', '--disallow-code-generation-from-strings'],
      network: 'NONE', isolation: 'READ_ONLY_NON_ROOT_DOCKER', relationToObservation: 'STRICTER_NO_NETWORK_NO_SYNTHETIC_HOME' } };
}

export function validatePreparedExecutionPolicy(value) {
  try {
    if (value?.profile === SCOPED_NODE_PROFILE) return canonicalJson(value) === canonicalJson(
      scopedPreparedExecutionPolicy({ collectorDigest: value.collectorDigest, observerDigest: value.observerDigest,
        egressAllowHosts: value.egressAllowHosts }, value.semantic));
    return canonicalJson(value) === canonicalJson(preparedExecutionPolicy({ collectorDigest: value.collectorDigest,
      observerDigest: value.observerDigest, egressAllowHosts: value.egressAllowHosts }));
  } catch { return false; }
}

export function scopedPreparedExecutionPolicy(observation, semantic) {
  if (!validateScopedReviewPolicy(semantic)) throw Error('PREPARED_SCOPED_POLICY_INVALID');
  return { ...preparedExecutionPolicy(observation), profile: SCOPED_NODE_PROFILE,
    semantic: scopedReviewPolicy(semantic.evidenceMode) };
}

// Commitment only: creating/verifying this object grants neither a PASS nor admission.
// No filesystem, Docker, provider, or candidate code is touched by these shared helpers.
export function createPreparedReleaseBinding(input) {
  if (!exact(input, ['sourceReleaseId', 'descriptor', 'executionPolicy']) || !bytes32.test(input.sourceReleaseId) ||
    !validatePreparedExecutionPolicy(input.executionPolicy)) throw Error('PREPARED_BINDING_INVALID');
  const descriptor = structuredClone(input.descriptor);
  const descriptorDigest = hashPreparedRuntimeDescriptor(descriptor);
  if (descriptor.stage !== 'CLOSURE_PREPARED' || descriptor.profile !== 'npm-closure-v1' ||
    !bytes32.test(descriptor.toolSurfaceHash)) throw Error('PREPARED_DISCOVERED_DESCRIPTOR_REQUIRED');
  const executionPolicy = structuredClone(input.executionPolicy);
  const manifest = { schemaVersion: 'mcpshield.prepared-release.v1', profile: 'npm-closure-v1',
    sourceReleaseId: input.sourceReleaseId, sourceArtifactDigest: descriptor.sourceTreeDigest,
    descriptorDigest, executionPolicyDigest: hash(executionPolicy) };
  return { ...manifest, artifactDigest: descriptorDigest, manifestDigest: hash(manifest),
    toolSurfaceHash: descriptor.toolSurfaceHash, descriptor, executionPolicy,
    finalImageDigest: descriptor.finalImageDigest, imageDigestKind: 'DOCKER_IMAGE_CONFIG_ID', platform: descriptor.platform };
}

export function validatePreparedReleaseBinding(value) {
  try {
    return canonicalJson(value) === canonicalJson(createPreparedReleaseBinding({ sourceReleaseId: value.sourceReleaseId,
      descriptor: value.descriptor, executionPolicy: value.executionPolicy }));
  } catch { return false; }
}
