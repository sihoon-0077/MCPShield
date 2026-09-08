import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import * as tar from 'tar';
import { canonicalJson } from '../../scanner/src/evidence.mjs';
import { validateRuntimePlatform } from './runtime-descriptor.mjs';
import { OCI_SOURCE_BUDGET_PROFILE, snapshotLimits } from '../../scanner/src/snapshot.mjs';

export const OCI_RUNTIME_LIMITS = Object.freeze({ files: 50_000, expandedBytes: 512 * 1024 * 1024, archiveBytes: 512 * 1024 * 1024 });
export { OCI_SOURCE_BUDGET_PROFILE } from '../../scanner/src/snapshot.mjs';
export const ociHash = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const sha = /^sha256:[a-f0-9]{64}$/;
const exact = (value, fields) => value && !Array.isArray(value) && Object.keys(value).sort().join() === [...fields].sort().join();
const fail = (code) => { throw Error(code); };
export const ociAbsolutePath = (value) => typeof value === 'string' && value.length <= 1024 && value.startsWith('/') &&
  !/[\x00-\x20\x7f\\]/.test(value) && (value === '/' || value.slice(1).split('/').every((part) => part && part !== '.' && part !== '..'));
export const OCI_OBSERVATION_POLICY = Object.freeze({ user: '1000:1000', rootFilesystem: 'READ_ONLY', capabilities: 'NONE',
  privilegeEscalation: 'DENIED', network: 'INTERNAL_SYNTHETIC_PROXY', environment: 'IMAGE_WHITELIST_PLUS_FIXED_SYNTHETIC',
  collector: 'EXTERNAL_MCP_CLIENT', filesystemObservation: 'NOT_OBSERVED', binarySemantic: 'NOT_REVIEWED' });

// Image environment is not forwarded to the trusted host client. Only this small
// inert image whitelist is retained in the candidate; fixed synthetic variables
// are added by the isolated observer and committed by the policy version.
export function checkedOciConfig(config) {
  const runtime = config?.config ?? {};
  const argv = [...(runtime.Entrypoint ?? []), ...(runtime.Cmd ?? [])];
  if (![runtime.Entrypoint ?? [], runtime.Cmd ?? []].every(Array.isArray) || !argv.length || argv.length > 32 ||
    argv.some((arg) => typeof arg !== 'string' || arg.length > 1024 || /[\x00-\x1f\x7f]/.test(arg)) ||
    !ociAbsolutePath(argv[0]) || argv[0] === '/') fail('OCI_ABSOLUTE_ENTRYPOINT_REQUIRED');
  const workingDirectory = runtime.WorkingDir || '/';
  if (!ociAbsolutePath(workingDirectory) || runtime.Volumes && Object.keys(runtime.Volumes).length ||
    runtime.OnBuild?.length) fail('OCI_MUTABLE_IMAGE_CONFIG_UNSUPPORTED');
  const env = runtime.Env ?? [];
  if (!Array.isArray(env) || env.length > 16) fail('OCI_ENVIRONMENT_UNSUPPORTED');
  const names = new Set();
  for (const item of env) {
    if (typeof item !== 'string' || item.length > 2048 || /[\x00-\x1f\x7f]/.test(item)) fail('OCI_ENVIRONMENT_UNSUPPORTED');
    const separator = item.indexOf('='), name = item.slice(0, separator), value = item.slice(separator + 1);
    if (separator < 1 || names.has(name) || !['PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ', 'PYTHONUNBUFFERED', 'PYTHONDONTWRITEBYTECODE'].includes(name)) fail('OCI_ENVIRONMENT_UNSUPPORTED');
    names.add(name);
    if (name === 'PATH' ? value.split(':').some((path) => !ociAbsolutePath(path)) : !/^[A-Za-z0-9_./+:-]{0,128}$/.test(value)) fail('OCI_ENVIRONMENT_UNSUPPORTED');
  }
  return { argv, workingDirectory, environmentDigest: ociHash(canonicalJson(env)) };
}

// Canonical final filesystem evidence, not Docker export's timestamp/order-sensitive
// raw tar hash. Layers/whiteouts are applied ONLY by Docker. No host extraction.
export function inspectOciFilesystem(bytes, { retainReviewSources = false, trustedEntries = [] } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1024 || bytes.length > OCI_RUNTIME_LIMITS.archiveBytes ||
    bytes.length % 512 || !new tar.Header(bytes).cksumValid) fail('OCI_FILESYSTEM_ARCHIVE_INVALID');
  const entries = [], paths = new Set(), reviewSources = [];
  const trusted = new Map(trustedEntries.map((entry) => [entry.path, canonicalJson(entry)]));
  let total = 0;
  let retainedBytes = 0;
  const sourceBudget = 8 * 1024 * 1024;
  const parser = tar.t({ sync: true, strict: true, onReadEntry(entry) {
    const path = entry.path.replace(/^\.\//, '').replace(/\/$/, '');
    if (!path || path === '.') { if (entry.type !== 'Directory' || entry.size !== 0) fail('OCI_FILESYSTEM_ENTRY_INVALID'); return; }
    if (!ociAbsolutePath(`/${path}`) || paths.has(path) || paths.size >= OCI_RUNTIME_LIMITS.files ||
      !['File', 'Directory', 'SymbolicLink', 'Link', 'CharacterDevice', 'BlockDevice', 'FIFO'].includes(entry.type) ||
      !Number.isSafeInteger(entry.size) || entry.size < 0 || (total += entry.size) > OCI_RUNTIME_LIMITS.expandedBytes ||
      !Number.isSafeInteger(entry.mode) || entry.mode < 0 || entry.mode > 0o7777 ||
      !Number.isSafeInteger(entry.uid) || entry.uid < 0 || !Number.isSafeInteger(entry.gid) || entry.gid < 0) fail('OCI_FILESYSTEM_ENTRY_INVALID');
    paths.add(path);
    const item = { path, type: entry.type, mode: entry.mode, uid: entry.uid, gid: entry.gid,
      link: ['Link', 'SymbolicLink'].includes(entry.type) ? entry.linkpath : null, digest: null };
    if (item.link !== null && (typeof item.link !== 'string' || item.link.length > 1024 || /[\x00-\x1f\x7f\\]/.test(item.link))) fail('OCI_FILESYSTEM_LINK_INVALID');
    if (entry.type === 'Link' && !ociAbsolutePath(`/${item.link}`)) fail('OCI_FILESYSTEM_LINK_INVALID');
    if (entry.type === 'CharacterDevice' || entry.type === 'BlockDevice') Object.assign(item, { deviceMajor: entry.devmaj, deviceMinor: entry.devmin });
    if (entry.type === 'File') {
      const hash = createHash('sha256');
      const chunks = retainReviewSources && entry.size <= sourceBudget - retainedBytes ? [] : null;
      entry.on('data', (chunk) => { hash.update(chunk); if (chunks) chunks.push(chunk); });
      entry.on('end', () => {
        item.digest = `sha256:${hash.digest('hex')}`;
        if (retainReviewSources && trusted.get(path) !== canonicalJson(item)) {
          const source = chunks && retainedBytes + entry.size <= sourceBudget ? Buffer.concat(chunks) : null;
          if (source) retainedBytes += source.length;
          reviewSources.push({ path, digest: item.digest, bytes: source });
        }
      });
    } else if (entry.size !== 0) fail('OCI_FILESYSTEM_ENTRY_INVALID');
    entries.push(item);
  } });
  parser.end(bytes);
  if (!entries.length || entries.some((entry) => entry.type === 'File' && !sha.test(entry.digest))) fail('OCI_FILESYSTEM_INCOMPLETE');
  entries.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return { algorithm: 'sha256-canonical-oci-rootfs-v1', digest: ociHash(canonicalJson(entries)), entries, bytes: total,
    ...(retainReviewSources ? { reviewSources, retainedSourceBytes: retainedBytes } : {}) };
}

export function resolveOciEntrypoint(filesystem, requestedPath) {
  if (!ociAbsolutePath(requestedPath) || requestedPath === '/') fail('OCI_ABSOLUTE_ENTRYPOINT_REQUIRED');
  const entries = new Map(filesystem.entries.map((entry) => [`/${entry.path}`, entry]));
  const chain = [], seen = new Set();
  let path = requestedPath;
  for (let hop = 0; hop < 32; hop++) {
    const parts = path.slice(1).split('/');
    let restarted = false;
    for (let index = 0; index < parts.length; index++) {
      const prefix = `/${parts.slice(0, index + 1).join('/')}`, entry = entries.get(prefix);
      if (!entry) fail('OCI_ENTRYPOINT_FILE_MISSING');
      if (['SymbolicLink', 'Link'].includes(entry.type)) {
        if (seen.has(prefix)) fail('OCI_ENTRYPOINT_LINK_CYCLE');
        seen.add(prefix); chain.push(entry);
        const target = entry.type === 'Link' ? `/${entry.link}` : posix.resolve(posix.dirname(prefix), entry.link);
        path = posix.join(target, ...parts.slice(index + 1));
        restarted = true; break;
      }
      if (index < parts.length - 1 && entry.type !== 'Directory') fail('OCI_ENTRYPOINT_ANCESTOR_INVALID');
      if (index === parts.length - 1) {
        if (entry.type !== 'File' || !(entry.mode & 0o111)) fail('OCI_ENTRYPOINT_NOT_EXECUTABLE');
        return { requestedPath, resolvedPath: path, contentDigest: entry.digest, linkChainDigest: ociHash(canonicalJson(chain)) };
      }
    }
    if (!restarted) break;
  }
  fail('OCI_ENTRYPOINT_LINK_LIMIT');
}

export function hashOciRuntimeDescriptor(value) {
  const fields = ['schemaVersion', 'profile', 'stage', 'sourceTreeDigest', 'sourceIndexDigest', 'manifestDigest', 'configDigest',
    'platform', 'finalImageDigest', 'imageDigestKind', 'rootfsDigest', 'entrypoint', 'argv', 'workingDirectory', 'environmentDigest', 'toolSurfaceHash', 'policy',
    'budgetProfile', 'sourceBytes', 'layerArchiveBytes', 'exportArchiveBytes'];
  if (!exact(value, fields) || value.schemaVersion !== 'mcpshield.oci-runtime.v1' || value.profile !== 'oci-container-v1' ||
    !['IMPORTED', 'OBSERVED'].includes(value.stage) || value.imageDigestKind !== 'DOCKER_IMAGE_CONFIG_ID') fail('OCI_RUNTIME_DESCRIPTOR_INVALID');
  if (value.budgetProfile !== OCI_SOURCE_BUDGET_PROFILE || !Number.isSafeInteger(value.sourceBytes) || value.sourceBytes < 1 ||
    value.sourceBytes > snapshotLimits(OCI_SOURCE_BUDGET_PROFILE).bytes ||
    !Number.isSafeInteger(value.layerArchiveBytes) || value.layerArchiveBytes < 0 ||
    !Number.isSafeInteger(value.exportArchiveBytes) || value.exportArchiveBytes < 1024 ||
    value.layerArchiveBytes + value.exportArchiveBytes > OCI_RUNTIME_LIMITS.archiveBytes) fail('OCI_RUNTIME_BUDGET_INVALID');
  for (const field of ['sourceTreeDigest', 'sourceIndexDigest', 'manifestDigest', 'configDigest', 'finalImageDigest', 'rootfsDigest', 'environmentDigest']) if (!sha.test(value[field])) fail('OCI_RUNTIME_DIGEST_INVALID');
  validateRuntimePlatform(value.platform);
  if (value.configDigest !== value.finalImageDigest || !exact(value.entrypoint, ['requestedPath', 'resolvedPath', 'contentDigest', 'linkChainDigest']) ||
    !ociAbsolutePath(value.entrypoint.requestedPath) || !ociAbsolutePath(value.entrypoint.resolvedPath) ||
    !sha.test(value.entrypoint.contentDigest) || !sha.test(value.entrypoint.linkChainDigest) ||
    !Array.isArray(value.argv) || value.argv.length < 1 || value.argv.length > 32 || value.argv[0] !== value.entrypoint.requestedPath ||
    value.argv.some((arg) => typeof arg !== 'string' || arg.length > 1024 || /[\x00-\x1f\x7f]/.test(arg)) ||
    !ociAbsolutePath(value.workingDirectory) || canonicalJson(value.policy) !== canonicalJson(OCI_OBSERVATION_POLICY) ||
    (value.stage === 'IMPORTED' ? value.toolSurfaceHash !== null : !/^0x[a-f0-9]{64}$/.test(value.toolSurfaceHash))) fail('OCI_RUNTIME_POLICY_INVALID');
  return ociHash(canonicalJson(value));
}
