import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { artifactDigest, toolSurfaceHash } from '../../scanner/src/scanner.mjs';
import { canonicalJson } from '../../scanner/src/evidence.mjs';
import { copyFixtureSnapshot, removeFixtureSnapshot, SNAPSHOT_LIMITS, snapshotLimits, OCI_SOURCE_BUDGET_PROFILE } from '../../scanner/src/snapshot.mjs';
import { preflightOciRuntime, validateRuntimePlatform } from './runtime-preflight.mjs';

const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const mediaTypes = 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json';

const JSON_LIMIT = 1024 * 1024;
function descriptor(value, max = SNAPSHOT_LIMITS.bytes) {
  if (!value || !digestPattern.test(value.digest) || !Number.isSafeInteger(value.size) || value.size < 0 || value.size > max) throw new TypeError('invalid or oversized OCI descriptor');
  if (value.urls?.length) throw new TypeError('foreign OCI layer URLs are not allowed');
  return value;
}

function verifyBlob(bytes, expected, max = SNAPSHOT_LIMITS.bytes) {
  descriptor(expected, max);
  if (bytes.length !== expected.size || digest(bytes) !== expected.digest) throw new Error('OCI_BLOB_INTEGRITY_MISMATCH');
  return bytes;
}

export async function inspectOciImage({ index, readBlob, platform = { os: 'linux', architecture: 'amd64' }, budgetProfile = 'fixture-v1' }) {
  const limits = snapshotLimits(budgetProfile);
  let verifiedBytes = Buffer.byteLength(JSON.stringify(index));
  if (verifiedBytes > JSON_LIMIT) throw Error('OCI_JSON_SIZE_LIMIT');
  const checkedRead = async (entry, max) => {
    descriptor(entry, max);
    if (verifiedBytes + entry.size > limits.bytes) throw Error('OCI_BLOB_TOTAL_SIZE_LIMIT');
    const bytes = verifyBlob(await readBlob(entry), entry, max);
    verifiedBytes += bytes.length;
    return bytes;
  };
  platform = validateRuntimePlatform(platform);
  let selected = index;
  let imageDigest = digest(Buffer.from(canonicalJson(index)));
  let imageBytes;
  for (let depth = 0; selected.manifests; depth++) {
    if (depth > 3 || !Array.isArray(selected.manifests) || selected.manifests.length > 128) throw new TypeError('OCI index limit exceeded');
    const matches = selected.manifests.filter((entry) => entry.platform?.os === platform.os && entry.platform?.architecture === platform.architecture);
    const match = matches.length === 1 && !matches[0].platform.variant ? matches[0]
      : matches.length === 0 && selected.manifests.length === 1 && !selected.manifests[0].platform ? selected.manifests[0] : null;
    if (!match) throw new TypeError('OCI platform is unsupported or ambiguous');
    imageBytes = await checkedRead(match, JSON_LIMIT);
    imageDigest = match.digest;
    selected = JSON.parse(imageBytes);
  }
  if (selected.schemaVersion !== 2 || !selected.config || !Array.isArray(selected.layers) || selected.layers.length > 128) throw new TypeError('invalid OCI image manifest');
  const configBytes = await checkedRead(selected.config, JSON_LIMIT);
  const config = JSON.parse(configBytes);
  if (config.os !== platform.os || config.architecture !== platform.architecture) throw new TypeError('OCI config platform mismatch');
  let layerBytes = 0;
  const layers = [];
  for (const layer of selected.layers) {
    descriptor(layer, limits.bytes);
    layerBytes += layer.size;
    if (layerBytes > limits.bytes) throw new Error('OCI_LAYER_SIZE_LIMIT');
    await checkedRead(layer, limits.bytes);
    layers.push({ digest: layer.digest, size: layer.size, mediaType: layer.mediaType });
  }
  const runtime = config.config ?? {};
  const user = runtime.User ?? '';
  const rootUser = user === '' || user === 'root' || user === '0' || user.startsWith('0:') || user.startsWith('root:');
  return { imageDigest, manifest: selected, config, layers, platform, layerBytes,
    runtime: { user, rootUser, entrypoint: runtime.Entrypoint ?? [], command: runtime.Cmd ?? [],
      environmentNames: (runtime.Env ?? []).map((item) => String(item).split('=')[0]), exposedPorts: Object.keys(runtime.ExposedPorts ?? {}) },
    findings: rootUser ? [{ code: 'OCI_ROOT_USER', severity: 'HIGH', requiresReview: true }] : [],
  };
}

async function boundedResponse(response, max = SNAPSHOT_LIMITS.bytes) {
  if (!response.ok || !response.body) throw new Error(`OCI registry returned HTTP ${response.status}`);
  const reader = response.body.getReader();
  let total = 0;
  const chunks = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > max) throw new Error('OCI_DOWNLOAD_SIZE_LIMIT');
      chunks.push(Buffer.from(value));
    }
  } catch (error) { await reader.cancel(); throw error; }
  return Buffer.concat(chunks);
}

export function parseOciLocator(locator) {
  const match = /^(ghcr\.io|registry-1\.docker\.io)\/([a-z0-9]+(?:[._/-][a-z0-9]+)*)(?:@(sha256:[a-f0-9]{64})|:([A-Za-z0-9_][A-Za-z0-9_.-]{0,127}))$/.exec(locator ?? '');
  if (!match) throw new TypeError('OCI locator must name an allowed registry, repository and explicit tag/digest');
  return { registry: match[1], repository: match[2], reference: match[3] ?? match[4] };
}

export async function resolveOciArtifact(source) {
  const budgetProfile = OCI_SOURCE_BUDGET_PROFILE, limits = snapshotLimits(budgetProfile);
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-oci-'));
  const artifactDir = join(workspace, 'artifact');
  const layoutDir = join(artifactDir, 'oci');
  await mkdir(artifactDir);
  try {
    let index;
    let readBlob;
    let originalLocator;
    let pinnedManifestDigest;
    if (source.type === 'oci-layout') {
      await copyFixtureSnapshot(source.path ?? source.locator, layoutDir, { profile: budgetProfile });
      const layoutBytes = await readFile(join(layoutDir, 'oci-layout'));
      if (layoutBytes.length > JSON_LIMIT) throw Error('OCI_JSON_SIZE_LIMIT');
      const layout = JSON.parse(layoutBytes);
      if (layout.imageLayoutVersion !== '1.0.0') throw new TypeError('unsupported OCI layout version');
      const indexBytes = await readFile(join(layoutDir, 'index.json'));
      if (indexBytes.length > JSON_LIMIT) throw Error('OCI_JSON_SIZE_LIMIT');
      index = JSON.parse(indexBytes);
      readBlob = async (entry) => readFile(join(layoutDir, 'blobs', 'sha256', descriptor(entry, limits.bytes).digest.slice(7)));
      originalLocator = 'oci-layout:local';
    } else {
      const parsed = parseOciLocator(source.locator);
      originalLocator = `${parsed.registry}/${parsed.repository}`;
      let bearer;
      let downloadedBytes = 0;
      const registryGet = async (path, accept, max = JSON_LIMIT) => {
        const url = `https://${parsed.registry}/v2/${parsed.repository}/${path}`;
        const request = () => fetch(url, { headers: { accept, ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) }, redirect: 'error', signal: AbortSignal.timeout(15_000) });
        let response = await request();
        if (response.status === 401 && !bearer) {
          // Anonymous pull tokens only; realm is fixed by registry, never trusted from a challenge header.
          const tokenUrl = parsed.registry === 'ghcr.io'
            ? new URL('https://ghcr.io/token') : new URL('https://auth.docker.io/token');
          tokenUrl.searchParams.set('service', parsed.registry === 'ghcr.io' ? 'ghcr.io' : 'registry.docker.io');
          tokenUrl.searchParams.set('scope', `repository:${parsed.repository}:pull`);
          const payload = JSON.parse(await boundedResponse(await fetch(tokenUrl, { redirect: 'error', signal: AbortSignal.timeout(15_000) }), 64 * 1024));
          bearer = payload.token ?? payload.access_token;
          if (typeof bearer !== 'string' || bearer.length > 32_000) throw new Error('invalid OCI anonymous pull token');
          response = await request();
        }
        const bytes = await boundedResponse(response, Math.min(max, limits.bytes - downloadedBytes));
        downloadedBytes += bytes.length;
        return bytes;
      };
      await mkdir(join(layoutDir, 'blobs', 'sha256'), { recursive: true });
      const initialBytes = await registryGet(`manifests/${parsed.reference}`, mediaTypes);
      pinnedManifestDigest = digest(initialBytes);
      if (digestPattern.test(parsed.reference) && pinnedManifestDigest !== parsed.reference) throw new Error('OCI_MANIFEST_INTEGRITY_MISMATCH');
      index = JSON.parse(initialBytes);
      await writeFile(join(layoutDir, 'index.json'), initialBytes);
      await writeFile(join(layoutDir, 'oci-layout'), canonicalJson({ imageLayoutVersion: '1.0.0' }));
      readBlob = async (entry) => {
        const manifest = /manifest|index/.test(entry.mediaType ?? '');
        const bytes = await registryGet(`${manifest ? 'manifests' : 'blobs'}/${entry.digest}`, manifest ? mediaTypes : 'application/octet-stream',
          /manifest|index|config/.test(entry.mediaType ?? '') ? JSON_LIMIT : limits.bytes);
        verifyBlob(bytes, entry, limits.bytes);
        await writeFile(join(layoutDir, 'blobs', 'sha256', entry.digest.slice(7)), bytes);
        return bytes;
      };
    }
    const inspection = await inspectOciImage({ index, readBlob, platform: source.platform, budgetProfile });
    const imageDigest = index.manifests ? inspection.imageDigest : pinnedManifestDigest ?? inspection.imageDigest;
    const name = `oci-image-${imageDigest.slice(7, 19)}`;
    // Legacy ScanResult requires semver; this is an explicit metadata snapshot alias, never an image version claim.
    const manifest = { name, version: '0.0.0', entrypoint: 'not-executable', tools: [], declaredEgress: [], surfaceUnknown: true };
    await writeFile(join(artifactDir, 'manifest.json'), canonicalJson(manifest));
    await writeFile(join(artifactDir, 'package.json'), canonicalJson({ name, version: '0.0.0', private: true }));
    const treeDigest = await artifactDigest(artifactDir, { profile: budgetProfile });
    const manifestDigest = digest(Buffer.from(canonicalJson(manifest)));
    const immutableReference = `${originalLocator}@${imageDigest}`;
    const metadata = { sourceType: 'oci', canonicalLocator: originalLocator, immutableReference,
      imageDigest, indexDigest: pinnedManifestDigest ?? digest(Buffer.from(canonicalJson(index))), artifactDigest: treeDigest, manifestDigest,
      name, version: '0.0.0', versionIsSnapshotAlias: true, surfaceKnown: false, toolSurfaceHash: toolSurfaceHash([]),
      retrievedAt: new Date().toISOString(), budgetProfile, publisherEvidence: [], runtime: inspection.runtime, imageFindings: inspection.findings,
      layers: inspection.layers, platform: inspection.platform, allLayerDigestsVerified: true, executionPerformed: false };
    metadata.runtimePreparation = preflightOciRuntime({ sourceDigest: imageDigest, sourceTreeDigest: treeDigest,
      runtime: inspection.runtime, platform: inspection.platform, builderImageDigest: source.builderImageDigest });
    return { artifactDir, root: artifactDir, releaseId: `${name}@0.0.0`, toolId: `oci:${originalLocator}`, version: '0.0.0', artifactUri: immutableReference,
      artifactDigest: treeDigest, manifestDigest, toolSurfaceHash: metadata.toolSurfaceHash, metadata, cleanup: () => removeFixtureSnapshot(workspace) };
  } catch (error) { await removeFixtureSnapshot(workspace); throw error; }
}
