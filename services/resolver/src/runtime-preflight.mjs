import { createHash } from 'node:crypto';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import semver from 'semver';
import { canonicalJson } from '../../scanner/src/evidence.mjs';
import { artifactDigest } from '../../scanner/src/scanner.mjs';
import { copyFixtureSnapshot, removeFixtureSnapshot } from '../../scanner/src/snapshot.mjs';

const hash = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const record = (value) => value && typeof value === 'object' && !Array.isArray(value);
const fail = (code) => { throw new Error(code); };
const dependencyFields = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const packageName = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const lockPath = /^(?:node_modules\/(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*)(?:\/node_modules\/(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*)*$/;

export { hashPreparedRuntimeDescriptor, validateRuntimePlatform } from './runtime-descriptor.mjs';
import { hashPreparedRuntimeDescriptor, validateRuntimePlatform, runtimeRelativePath as relativePath } from './runtime-descriptor.mjs';

function argvValid(argv) {
  return Array.isArray(argv) && argv.length > 0 && argv.length <= 32 && argv.every((arg) =>
    typeof arg === 'string' && arg.length > 0 && arg.length <= 1024 && !/[\x00-\x1f\x7f]/.test(arg));
}

function descriptor({ profile, sourceDigest, sourceTreeDigest, platform = null, builderImageDigest = null }) {
  return { schemaVersion: 'mcpshield.prepared-runtime.v1', stage: 'PREFLIGHT', profile, sourceDigest, sourceTreeDigest,
    lockDigest: null, lockOrigin: profile === 'oci-image-v1' ? 'NOT_APPLICABLE' : null, builderImageDigest,
    platform: platform === null ? null : validateRuntimePlatform(platform), finalImageDigest: null, toolSurfaceHash: null,
    entrypoint: null, argv: null, policy: { acquisitionNetwork: 'REGISTRY_ONLY_SEPARATE', installNetwork: 'NONE',
      installScripts: 'DISABLED', executionNetwork: 'INTERNAL_SYNTHETIC_PROXY', user: 'NON_ROOT', rootFilesystem: 'READ_ONLY' } };
}

function report(value, issues, checks) {
  return { status: 'INCONCLUSIVE', ready: false, executionPerformed: false, descriptor: value,
    descriptorDigest: hashPreparedRuntimeDescriptor(value), checks,
    issues: [...new Set(issues.map((code) => /^RUNTIME_[A-Z_]+$|^OCI_[A-Z_]+$/.test(code) ? code : 'RUNTIME_PREFLIGHT_FAILED'))],
    // Even a syntactically valid supplied lock is not a verified installed dependency closure.
    pending: ['ISOLATED_RUNTIME_PREPARATION', 'FINAL_IMAGE_DIGEST', 'ACTUAL_MCP_DISCOVERY', 'RUNTIME_OBSERVATION'] };
}

function strongIntegrity(value) {
  if (typeof value !== 'string' || value.length > 1024) return false;
  const tokens = value.split(/\s+/);
  return tokens.length > 0 && tokens.every((token) => {
    const match = /^(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})$/.exec(token);
    if (!match) return false;
    const bytes = Buffer.from(match[2], 'base64');
    return bytes.length === Number(match[1].slice(3)) / 8 && bytes.toString('base64') === match[2];
  });
}

function dependencyMap(value) {
  if (value === undefined) return {};
  if (!record(value) || Object.keys(value).length > 1024 || Object.entries(value).some(([name, spec]) =>
    !packageName.test(name) || typeof spec !== 'string' || spec.length > 256 || !semver.validRange(spec))) fail('RUNTIME_DEPENDENCY_SPEC_UNSUPPORTED');
  return value;
}

export function validateLocklessPackageDependencies(pkg) {
  if (!record(pkg)) fail('RUNTIME_PACKAGE_JSON_INVALID');
  for (const field of dependencyFields) dependencyMap(pkg[field]);
  if (pkg.workspaces !== undefined || pkg.overrides !== undefined ||
    [pkg.bundleDependencies, pkg.bundledDependencies].some((value) => value !== undefined && (!Array.isArray(value) || value.length))) {
    fail('RUNTIME_DEPENDENCY_LAYOUT_UNSUPPORTED');
  }
}

function inspectLock(bytes, pkg) {
  if (bytes.length > 1024 * 1024) fail('RUNTIME_LOCK_SIZE_LIMIT');
  let lock;
  try { lock = JSON.parse(bytes); } catch { fail('RUNTIME_LOCK_JSON_INVALID'); }
  if (!record(lock) || ![2, 3].includes(lock.lockfileVersion) || !record(lock.packages) ||
    Object.keys(lock.packages).length > 1024 || !record(lock.packages[''])) fail('RUNTIME_LOCK_FORMAT_UNSUPPORTED');
  const root = lock.packages[''];
  if (lock.name !== pkg.name || lock.version !== pkg.version || root.name !== pkg.name || root.version !== pkg.version) fail('RUNTIME_LOCK_IDENTITY_MISMATCH');
  for (const field of dependencyFields) {
    if (canonicalJson(dependencyMap(pkg[field])) !== canonicalJson(dependencyMap(root[field]))) fail('RUNTIME_LOCK_MANIFEST_MISMATCH');
  }
  let packages = 0;
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (path === '') continue;
    if (!lockPath.test(path) || !relativePath(path) || !record(entry) || entry.link || entry.inBundle ||
      typeof entry.version !== 'string' || semver.valid(entry.version) !== entry.version) fail('RUNTIME_LOCK_ENTRY_UNSUPPORTED');
    if (!strongIntegrity(entry.integrity)) fail('RUNTIME_LOCK_INTEGRITY_INVALID');
    let url;
    try { url = new URL(entry.resolved); } catch { fail('RUNTIME_LOCK_REGISTRY_INVALID'); }
    if (url.href !== entry.resolved || url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' ||
      url.port || url.username || url.password || url.search || url.hash) fail('RUNTIME_LOCK_REGISTRY_INVALID');
    for (const field of dependencyFields) dependencyMap(entry[field]);
    packages++;
  }
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    for (const name of Object.keys(dependencyMap(pkg[field]))) {
      if (!Object.hasOwn(lock.packages, `node_modules/${name}`)) fail('RUNTIME_LOCK_DEPENDENCY_MISSING');
    }
  }
  return { packages, integritySyntax: 'VALID', archiveIntegrityVerified: false, graphVerifiedByNpm: false };
}

function selectBin(pkg, binName) {
  let bins = pkg.bin;
  if (typeof bins === 'string') bins = { [pkg.name.split('/').at(-1)]: bins };
  if (!record(bins) || Object.keys(bins).length === 0 || Object.keys(bins).length > 32 ||
    Object.keys(bins).some((name) => !/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/.test(name))) fail('RUNTIME_BIN_REQUIRED');
  if (binName === undefined && Object.keys(bins).length !== 1) fail('RUNTIME_BIN_SELECTION_REQUIRED');
  const selected = binName ?? Object.keys(bins)[0];
  if (typeof selected !== 'string' || !Object.hasOwn(bins, selected)) fail('RUNTIME_BIN_SELECTION_INVALID');
  const path = bins[selected];
  if (!relativePath(path) || !/\.(?:mjs|cjs|js)$/.test(path)) fail('RUNTIME_BIN_PATH_UNSUPPORTED');
  return path;
}

export async function preflightNpmRuntime({ root, sourceDigest, sourceTreeDigest, binName, platform = null, builderImageDigest = null, generatedLock }) {
  if (generatedLock !== undefined) {
    if (!Buffer.isBuffer(generatedLock) || generatedLock.length > 1024 * 1024) throw Error('RUNTIME_GENERATED_LOCK_INVALID');
    generatedLock = Buffer.from(generatedLock);
  }
  const value = descriptor({ profile: 'npm-closure-v1', sourceDigest, sourceTreeDigest, platform, builderImageDigest });
  hashPreparedRuntimeDescriptor(value);
  const issues = [];
  const checks = { snapshotVerified: false, entrypointVerified: false, lock: null };
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-preflight-'));
  const snapshot = join(workspace, 'artifact');
  try {
    // Reuse the bounded, no-links, stable-copy boundary; never inspect executable files through caller-owned paths.
    try { await copyFixtureSnapshot(root, snapshot); } catch { fail('RUNTIME_SOURCE_SNAPSHOT_INVALID'); }
    if (await artifactDigest(snapshot) !== sourceTreeDigest) fail('RUNTIME_SOURCE_DIGEST_MISMATCH');
    checks.snapshotVerified = true;
    let pkg;
    try { pkg = JSON.parse(await readFile(join(snapshot, 'package.json'), 'utf8')); } catch { fail('RUNTIME_PACKAGE_JSON_INVALID'); }
    if (!record(pkg) || typeof pkg.name !== 'string' || !packageName.test(pkg.name) ||
      typeof pkg.version !== 'string' || semver.valid(pkg.version) !== pkg.version) fail('RUNTIME_PACKAGE_IDENTITY_INVALID');
    // Classify unsupported local/workspace/URL/git/alias layouts before any solver starts.
    validateLocklessPackageDependencies(pkg);
    try {
      const path = selectBin(pkg, binName);
      let bytes;
      try { bytes = await readFile(join(snapshot, path)); } catch { fail('RUNTIME_BIN_FILE_MISSING'); }
      value.entrypoint = { path, digest: hash(bytes) };
      value.argv = ['/usr/local/bin/node', `/app/${path}`];
      checks.entrypointVerified = true;
    } catch (error) { issues.push(error.message); }
    const locks = [];
    for (const name of ['npm-shrinkwrap.json', 'package-lock.json']) {
      try { locks.push({ name, bytes: await readFile(join(snapshot, name)) }); }
      catch (error) { if (error.code !== 'ENOENT') fail('RUNTIME_LOCK_UNREADABLE'); }
    }
    if (generatedLock !== undefined && locks.length) fail('RUNTIME_LOCK_ORIGIN_AMBIGUOUS');
    if (generatedLock !== undefined) locks.push({ name: 'package-lock.json', bytes: generatedLock });
    // npm prefers shrinkwrap. Reject different coexisting locks rather than silently commit the ignored one.
    if (locks.length === 2 && !locks[0].bytes.equals(locks[1].bytes)) issues.push('RUNTIME_LOCK_AMBIGUOUS');
    else if (!locks.length) issues.push('RUNTIME_LOCK_REQUIRED');
    else {
      try {
        checks.lock = inspectLock(locks[0].bytes, pkg);
        value.lockDigest = hash(locks[0].bytes);
        value.lockOrigin = generatedLock === undefined ? 'SUPPLIED' : 'RESOLVER_GENERATED';
      } catch (error) { issues.push(error.message); }
    }
  } catch (error) {
    issues.push(/^RUNTIME_[A-Z_]+$/.test(error.message) ? error.message : 'RUNTIME_PREFLIGHT_FAILED');
  } finally { await removeFixtureSnapshot(workspace); }
  if (!platform) issues.push('RUNTIME_PLATFORM_REQUIRED');
  if (!builderImageDigest) issues.push('RUNTIME_BUILDER_DIGEST_REQUIRED');
  return report(value, issues, checks);
}

export function preflightOciRuntime({ sourceDigest, sourceTreeDigest, runtime, platform, builderImageDigest = null }) {
  const value = descriptor({ profile: 'oci-image-v1', sourceDigest, sourceTreeDigest, platform, builderImageDigest });
  const issues = ['OCI_ENTRYPOINT_FILESYSTEM_UNVERIFIED', 'OCI_GENERIC_OBSERVATION_REQUIRED'];
  const entrypoint = runtime?.entrypoint;
  const command = runtime?.command;
  if (!Array.isArray(entrypoint) || !Array.isArray(command) || !argvValid([...entrypoint, ...command]) ||
    [...entrypoint, ...command].some((arg) => /(?:^|\/)\.{1,2}(?:\/|$)/.test(arg))) issues.push('RUNTIME_OCI_ARGV_INVALID');
  else value.argv = [...entrypoint, ...command];
  if (runtime?.rootUser !== false) issues.push('RUNTIME_OCI_NON_ROOT_REQUIRED');
  if (!builderImageDigest) issues.push('RUNTIME_BUILDER_DIGEST_REQUIRED');
  return report(value, issues, { imageFilesystemVerified: false, entrypointVerified: false, lock: null });
}
