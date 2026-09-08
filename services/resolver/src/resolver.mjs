import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import * as tar from 'tar';
import semver from 'semver';
import { artifactDigest, loadManifest, toolSurfaceHash } from '../../scanner/src/scanner.mjs';
import { canonicalJson } from '../../scanner/src/evidence.mjs';
import { copyFixtureSnapshot, removeFixtureSnapshot, SNAPSHOT_LIMITS } from '../../scanner/src/snapshot.mjs';
import { preflightNpmRuntime } from './runtime-preflight.mjs';

export const RESOLVER_LIMITS = Object.freeze({ downloadBytes: 16 * 1024 * 1024, expandedBytes: 20 * 1024 * 1024, files: 1024, ratio: 200, timeoutMs: 15_000 });
const packageName = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

export async function downloadRegistryUrl(value, maxBytes = RESOLVER_LIMITS.downloadBytes, { signal } = {}) {
  const url = new URL(value);
  // Public ingestion is intentionally restricted to the registry, never an arbitrary SSRF-capable fetch proxy.
  if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.port || url.username || url.password || url.hash) {
    throw new TypeError('only HTTPS registry.npmjs.org sources are allowed');
  }
  const response = await fetch(url, { redirect: 'error', signal: AbortSignal.any([AbortSignal.timeout(RESOLVER_LIMITS.timeoutMs), ...(signal ? [signal] : [])]), headers: { accept: 'application/json, application/octet-stream' } });
  if (!response.ok || !response.body) throw new Error(`registry returned HTTP ${response.status}`);
  const reader = response.body.getReader();
  let bytes = 0;
  const chunks = [];
  try {
    while (true) {
      const { done, value: chunk } = await reader.read();
      if (done) break;
      bytes += chunk.length;
      if (bytes > maxBytes) throw new Error('ARTIFACT_SIZE_LIMIT');
      chunks.push(Buffer.from(chunk));
    }
  } catch (error) { await reader.cancel(); throw error; }
  return Buffer.concat(chunks);
}

export function resolveNpmVersion(spec, metadata) {
  if (typeof spec !== 'string' || spec.length > 256) throw new TypeError('invalid npm spec');
  const separator = spec.lastIndexOf('@');
  const name = separator > 0 ? spec.slice(0, separator) : spec;
  const requested = separator > 0 ? spec.slice(separator + 1) : 'latest';
  if (!packageName.test(name) || metadata.name !== name) throw new TypeError('npm package identity mismatch');
  const version = metadata['dist-tags']?.[requested] ?? semver.maxSatisfying(Object.keys(metadata.versions ?? {}), requested);
  if (!version || !semver.valid(version) || !metadata.versions?.[version]) throw new TypeError('npm version did not resolve to an exact release');
  const release = metadata.versions[version];
  if (release.name !== name || release.version !== version || !release.dist?.tarball) throw new TypeError('registry release identity mismatch');
  return { name, version, release };
}

export function validateIntegrity(bytes, integrity) {
  if (!integrity) return false;
  if (typeof integrity !== 'string' || integrity.length > 1024) throw new TypeError('invalid artifact integrity');
  const candidates = integrity.split(/\s+/).map((token) => /^(sha512|sha384|sha256|sha1)-([A-Za-z0-9+/]+={0,2})$/.exec(token)).filter(Boolean);
  for (const algorithm of ['sha512', 'sha384', 'sha256', 'sha1']) {
    const strongest = candidates.filter((item) => item[1] === algorithm);
    if (!strongest.length) continue;
    if (!strongest.some((item) => createHash(algorithm).update(bytes).digest('base64') === item[2])) throw new Error('ARTIFACT_INTEGRITY_MISMATCH');
    return true;
  }
  throw new TypeError('unsupported artifact integrity');
}

// This accepts bytes for offline/air-gapped uploads as well as the registry path; it never runs package scripts.
export async function extractNpmArchive(bytes, outputDir, integrity) {
  if (!Buffer.isBuffer(bytes) || bytes.length > RESOLVER_LIMITS.downloadBytes) throw new Error('ARTIFACT_SIZE_LIMIT');
  const integrityVerified = validateIntegrity(bytes, integrity);
  let expanded;
  try {
    expanded = bytes[0] === 0x1f && bytes[1] === 0x8b ? gunzipSync(bytes, { maxOutputLength: RESOLVER_LIMITS.expandedBytes }) : bytes;
  } catch { throw new Error('ARTIFACT_ARCHIVE_BOMB_OR_INVALID_GZIP'); }
  if (expanded.length > RESOLVER_LIMITS.expandedBytes || expanded.length / Math.max(1, bytes.length) > RESOLVER_LIMITS.ratio) throw new Error('ARTIFACT_ARCHIVE_BOMB');
  // Do not let tar auto-detect another compression format after our bounded gzip step.
  if (expanded.length < 1024 || expanded.length % 512 !== 0 || !new tar.Header(expanded).cksumValid) throw new Error('ARTIFACT_INVALID_TAR');
  const seen = new Set();
  let files = 0;
  let contentBytes = 0;
  const inspect = (entry) => {
    const name = entry.path.replace(/\/$/, '');
    const parts = name.split('/');
    if (parts[0] !== 'package' || !['File', 'Directory'].includes(entry.type) || entry.linkpath ||
      parts.some((part) => !part || part === '.' || part === '..' || /[\\:\x00-\x1f\x7f]/.test(part) || /[. ]$/.test(part) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) throw new Error('ARTIFACT_UNSAFE_ARCHIVE_ENTRY');
    const normalized = name.normalize('NFC').toLowerCase();
    if (seen.has(normalized)) throw new Error('ARTIFACT_DUPLICATE_ARCHIVE_ENTRY');
    seen.add(normalized);
    if (entry.type === 'File') {
      files += 1;
      contentBytes += entry.size;
      if (files > RESOLVER_LIMITS.files || !Number.isSafeInteger(entry.size) || entry.size < 0 || contentBytes > SNAPSHOT_LIMITS.bytes) throw new Error('ARTIFACT_ARCHIVE_LIMIT');
    }
    if (seen.size > RESOLVER_LIMITS.files * 2) throw new Error('ARTIFACT_ARCHIVE_LIMIT');
  };
  // Validate all entries before any write. tar handles the archive format, PAX and checksum validation.
  const listing = tar.t({ sync: true, strict: true, onReadEntry: inspect });
  listing.end(expanded);
  if (!files || !seen.has('package/package.json')) throw new Error('ARTIFACT_PACKAGE_JSON_REQUIRED');
  await mkdir(outputDir, { mode: 0o700 });
  tar.x({ cwd: outputDir, sync: true, strict: true, strip: 1, noMtime: true, preservePaths: false }).end(expanded);
  return { archiveDigest: sha256(bytes), integrityVerified, sizeBytes: bytes.length, expandedBytes: contentBytes, files };
}

export async function resolveArtifact(input) {
  const source = input.source ?? (input.sourceType === 'local' ? { type: 'local', path: input.locator }
    : input.sourceType === 'npm' ? { type: 'npm', spec: input.locator }
      : { type: input.sourceType, url: input.locator, integrity: input.integrity });
  if (source?.type === 'oci' || source?.type === 'oci-layout') {
    const { resolveOciArtifact } = await import('./oci.mjs');
    return resolveOciArtifact({ ...source, locator: source.locator ?? source.url ?? input.locator });
  }
  if (!source || !['local', 'npm', 'tarball'].includes(source.type)) throw new TypeError('unsupported artifact source');
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-resolver-'));
  const artifactDir = join(workspace, 'artifact');
  let metadata;
  try {
    if (source.type === 'local') {
      const snapshot = await copyFixtureSnapshot(source.path, artifactDir);
      metadata = { sourceType: 'local', originalUrl: null, sizeBytes: snapshot.bytes, files: snapshot.files, publisherEvidence: [] };
    } else {
      let url = source.url;
      let integrity = source.integrity;
      let resolved;
      if (source.type === 'npm') {
        if (typeof source.spec !== 'string') throw new TypeError('npm spec is required');
        const separator = source.spec.lastIndexOf('@');
        const name = separator > 0 ? source.spec.slice(0, separator) : source.spec;
        if (!packageName.test(name)) throw new TypeError('invalid npm package name');
        const document = JSON.parse((await downloadRegistryUrl(`https://registry.npmjs.org/${encodeURIComponent(name)}`, 8 * 1024 * 1024)).toString('utf8'));
        resolved = resolveNpmVersion(source.spec, document);
        url = resolved.release.dist.tarball;
        integrity = resolved.release.dist.integrity ?? (resolved.release.dist.shasum ? `sha1-${Buffer.from(resolved.release.dist.shasum, 'hex').toString('base64')}` : undefined);
        if (!integrity) throw new Error('registry integrity missing');
      }
      const bytes = await downloadRegistryUrl(url);
      const archive = await extractNpmArchive(bytes, artifactDir, integrity);
      const pkg = JSON.parse(await readFile(join(artifactDir, 'package.json'), 'utf8'));
      if (resolved && (pkg.name !== resolved.name || pkg.version !== resolved.version)) throw new Error('archive package identity differs from registry');
      metadata = { sourceType: source.type, originalUrl: url, ...archive,
        publisherEvidence: (resolved?.release.maintainers ?? []).slice(0, 32).filter((item) => typeof item.name === 'string').map(({ name }) => ({ type: 'REGISTRY_DECLARED_MAINTAINER', name, verified: false })),
        provenance: { integrity: integrity ?? null, signatureVerified: false },
      };
    }
    const manifest = await loadManifest(artifactDir, true);
    if (source.type !== 'local') {
      const pkg = JSON.parse(await readFile(join(artifactDir, 'package.json'), 'utf8'));
      if (manifest.name !== pkg.name || manifest.version !== pkg.version) throw new Error('manifest identity differs from package identity');
    }
    const digest = await artifactDigest(artifactDir);
    const manifestDigest = sha256(canonicalJson(manifest));
    const releaseId = `${manifest.name}@${manifest.version}`;
    const locator = `${source.type === 'local' ? 'local' : 'npm'}:${releaseId}`;
    metadata = { ...metadata, name: manifest.name, version: manifest.version, retrievedAt: new Date().toISOString(),
      canonicalLocator: locator, immutableReference: `${locator}#${metadata.archiveDigest ?? digest}`, artifactDigest: digest,
      manifestDigest, toolSurfaceHash: toolSurfaceHash(manifest.tools), surfaceKnown: !manifest.surfaceUnknown,
      artifactDigestAlgorithm: 'sha256-sorted-path-nul-content-nul-v1' };
    // Additive metadata only: do not replace legacy v1 identity or imply that dependencies were installed.
    metadata.runtimePreparation = await preflightNpmRuntime({ root: artifactDir, sourceDigest: metadata.archiveDigest ?? digest,
      sourceTreeDigest: digest, binName: source.binName, platform: source.platform, builderImageDigest: source.builderImageDigest });
    return { artifactDir, root: artifactDir, releaseId, toolId: `npm:${manifest.name}`, version: manifest.version,
      artifactUri: metadata.immutableReference, artifactDigest: digest, manifestDigest, toolSurfaceHash: metadata.toolSurfaceHash,
      metadata, cleanup: () => removeFixtureSnapshot(workspace) };
  } catch (error) { await removeFixtureSnapshot(workspace); throw error; }
}
