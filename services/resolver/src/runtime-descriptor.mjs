import { createHash } from 'node:crypto';
import { canonicalJson } from '../../scanner/src/evidence.mjs';

const hash = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const record = (value) => value && typeof value === 'object' && !Array.isArray(value);
const fail = (code) => { throw new Error(code); };

export function runtimeRelativePath(value) {
  return typeof value === 'string' && value.length <= 512 && /^[A-Za-z0-9_@./-]+$/.test(value) &&
    value.split('/').every((part) => part && part !== '.' && part !== '..' && !/[. ]$/.test(part) &&
      !/^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part));
}

export function validateRuntimePlatform(platform) {
  if (!record(platform) || Object.keys(platform).some((key) => !['os', 'architecture'].includes(key)) ||
    platform.os !== 'linux' || !['amd64', 'arm64'].includes(platform.architecture)) fail('RUNTIME_PLATFORM_UNSUPPORTED');
  return { os: platform.os, architecture: platform.architecture };
}

function argvValid(argv) {
  return Array.isArray(argv) && argv.length > 0 && argv.length <= 32 && argv.every((arg) =>
    typeof arg === 'string' && arg.length > 0 && arg.length <= 1024 && !/[\x00-\x1f\x7f]/.test(arg));
}

// A descriptor is an identity commitment, NOT an attestation or permission to execute.
// Preflight/closure preparation never grants READY, even with fully populated caller-supplied fields.
export function hashPreparedRuntimeDescriptor(value) {
  const fields = ['schemaVersion', 'stage', 'profile', 'sourceDigest', 'sourceTreeDigest', 'lockDigest', 'lockOrigin',
    'builderImageDigest', 'platform', 'finalImageDigest', 'toolSurfaceHash', 'entrypoint', 'argv', 'policy'];
  if (!record(value) || Object.keys(value).length !== fields.length || fields.some((key) => !Object.hasOwn(value, key)) ||
    value.schemaVersion !== 'mcpshield.prepared-runtime.v1' || !['PREFLIGHT', 'CLOSURE_PREPARED'].includes(value.stage) ||
    !['npm-closure-v1', 'oci-image-v1'].includes(value.profile)) fail('RUNTIME_DESCRIPTOR_INVALID');
  for (const key of ['sourceDigest', 'sourceTreeDigest']) if (!digestPattern.test(value[key])) fail('RUNTIME_DESCRIPTOR_DIGEST_INVALID');
  for (const key of ['lockDigest', 'builderImageDigest', 'finalImageDigest']) {
    if (value[key] !== null && !digestPattern.test(value[key])) fail('RUNTIME_DESCRIPTOR_DIGEST_INVALID');
  }
  if (value.profile === 'oci-image-v1') {
    if (value.lockOrigin !== 'NOT_APPLICABLE' || value.lockDigest !== null) fail('RUNTIME_LOCK_ORIGIN_INVALID');
  } else if (value.lockDigest === null ? value.lockOrigin !== null : !['SUPPLIED', 'RESOLVER_GENERATED'].includes(value.lockOrigin)) {
    fail('RUNTIME_LOCK_ORIGIN_INVALID');
  }
  if (value.platform !== null) validateRuntimePlatform(value.platform);
  if (value.toolSurfaceHash !== null && !/^0x[a-f0-9]{64}$/.test(value.toolSurfaceHash)) fail('RUNTIME_SURFACE_HASH_INVALID');
  if (value.argv !== null && !argvValid(value.argv)) fail('RUNTIME_ARGV_INVALID');
  if (value.entrypoint !== null) {
    if (!record(value.entrypoint) || Object.keys(value.entrypoint).sort().join(',') !== 'digest,path' ||
      !runtimeRelativePath(value.entrypoint.path) || !digestPattern.test(value.entrypoint.digest) ||
      value.profile !== 'npm-closure-v1' || canonicalJson(value.argv) !== canonicalJson(['/usr/local/bin/node', `/app/${value.entrypoint.path}`])) {
      fail('RUNTIME_ENTRYPOINT_INVALID');
    }
  } else if (value.profile === 'npm-closure-v1' && value.argv !== null) fail('RUNTIME_ENTRYPOINT_INVALID');
  const policy = { acquisitionNetwork: 'REGISTRY_ONLY_SEPARATE', installNetwork: 'NONE', installScripts: 'DISABLED',
    executionNetwork: 'INTERNAL_SYNTHETIC_PROXY', user: 'NON_ROOT', rootFilesystem: 'READ_ONLY' };
  if (canonicalJson(value.policy) !== canonicalJson(policy)) fail('RUNTIME_POLICY_INVALID');
  if (value.stage === 'CLOSURE_PREPARED' && (value.profile !== 'npm-closure-v1' || !value.lockDigest ||
    !value.builderImageDigest || !value.finalImageDigest || !value.entrypoint || !value.platform)) fail('RUNTIME_PREPARATION_INCOMPLETE');
  return hash(canonicalJson(value));
}


