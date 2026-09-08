import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import * as tar from 'tar';
import { inspectOciImage } from './oci.mjs';
import { runRuntimeDocker } from './npm-closure.mjs';
import { artifactDigest } from '../../scanner/src/scanner.mjs';
import { copyFixtureSnapshot, removeFixtureSnapshot, OCI_SOURCE_BUDGET_PROFILE } from '../../scanner/src/snapshot.mjs';
import { canonicalJson } from '../../scanner/src/evidence.mjs';
import { checkedOciConfig, hashOciRuntimeDescriptor, inspectOciFilesystem, resolveOciEntrypoint,
  ociHash, OCI_OBSERVATION_POLICY, OCI_RUNTIME_LIMITS } from './oci-runtime-descriptor.mjs';
import { validateRuntimePlatform } from './runtime-descriptor.mjs';

const hashPattern = /^sha256:[a-f0-9]{64}$/;

// Validate expansion/diff IDs, not layer application. Docker alone interprets
// whiteouts and constructs the final filesystem; no archive is extracted on host.
export function inspectOciLayerBudget(layers, config) {
  if (config.rootfs?.type !== 'layers' || !Array.isArray(config.rootfs.diff_ids) || config.rootfs.diff_ids.length !== layers.length) throw Error('OCI_DIFF_ID_INVALID');
  let expanded = 0;
  let entries = 0;
  for (const [index, layer] of layers.entries()) {
    let bytes;
    if (['application/vnd.oci.image.layer.v1.tar+gzip', 'application/vnd.docker.image.rootfs.diff.tar.gzip'].includes(layer.mediaType)) {
      try { bytes = gunzipSync(layer.bytes, { maxOutputLength: OCI_RUNTIME_LIMITS.archiveBytes - expanded }); }
      catch { throw Error('OCI_LAYER_EXPANSION_FAILED'); }
    } else if (layer.mediaType === 'application/vnd.oci.image.layer.v1.tar') bytes = layer.bytes;
    else throw Error('OCI_LAYER_MEDIA_UNSUPPORTED');
    expanded += bytes.length;
    if (expanded > OCI_RUNTIME_LIMITS.archiveBytes || ociHash(bytes) !== config.rootfs.diff_ids[index]) throw Error('OCI_LAYER_DIFF_ID_OR_BUDGET_INVALID');
    // This is tar structure/size inspection only, not a merged filesystem.
    entries += inspectOciFilesystem(bytes).entries.length;
    if (entries > OCI_RUNTIME_LIMITS.files) throw Error('OCI_LAYER_ENTRY_BUDGET_INVALID');
  }
  return { expandedArchiveBytes: expanded, entries, layerCount: layers.length, diffIdsVerified: true, appliedBy: 'NATIVE_DOCKER_ONLY' };
}

export async function inspectImportedOciRuntime({ descriptor, expectedDescriptorDigest, trustedEntries, retainReviewSources = false, timeoutMs }) {
  if (hashOciRuntimeDescriptor(descriptor) !== expectedDescriptorDigest) throw Error('OCI_RUNTIME_IDENTITY_MISMATCH');
  if (process.platform !== 'linux') throw Error('OCI_LINUX_DOCKER_REQUIRED');
  return inspectImage(descriptor.finalImageDigest, descriptor.platform, descriptor, descriptor.layerArchiveBytes, { trustedEntries, retainReviewSources, timeoutMs });
}

// Native export only: the fixed command is never started and no candidate argv
// is interpreted. Also used to independently catalogue an operator-approved base.
export async function exportOciFilesystem({ imageDigest, platform, archiveBudget = OCI_RUNTIME_LIMITS.archiveBytes, trustedEntries, retainReviewSources = false, timeoutMs = 40_000 }) {
  if (!hashPattern.test(imageDigest) || !Number.isSafeInteger(archiveBudget) || archiveBudget < 1024 || archiveBudget > OCI_RUNTIME_LIMITS.archiveBytes) throw Error('OCI_EXPORT_INPUT_INVALID');
  validateRuntimePlatform(platform);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 40_000) throw Error('OCI_EXPORT_BUDGET_INVALID');
  if (process.platform !== 'linux') throw Error('OCI_LINUX_DOCKER_REQUIRED');
  const deadline = Date.now() + timeoutMs;
  const run = (args, cap, max) => {
    if (Date.now() >= deadline) throw Error('OCI_EXPORT_TIMEOUT');
    return runRuntimeDocker(args, Math.min(cap, deadline - Date.now()), max);
  };
  const container = `mcpshield-oci-inspect-${randomUUID()}`;
  try {
    const image = JSON.parse(await run(['image', 'inspect', imageDigest, '--format', '{{json .}}'], 5000));
    if (image.Id !== imageDigest || image.Os !== platform.os || image.Architecture !== platform.architecture) throw Error('OCI_IMPORTED_IMAGE_IDENTITY_MISMATCH');
    await run(['create', '--pull=never', '--name', container, '--network=none', '--read-only', '--user=1000:1000',
      '--cap-drop=ALL', '--security-opt=no-new-privileges', '--no-healthcheck', '--entrypoint=/bin/false', imageDigest], 5000);
    const archive = await run(['export', container], 30_000, archiveBudget);
    const filesystem = inspectOciFilesystem(archive, { trustedEntries, retainReviewSources });
    if (Date.now() >= deadline) throw Error('OCI_EXPORT_TIMEOUT');
    return { image, filesystem, exportArchiveBytes: archive.length, candidateExecutionPerformed: false };
  } finally { try { await runRuntimeDocker(['rm', '-f', '-v', container], 5000); } catch { /* exact never-started container and its anonymous volumes */ } }
}

async function inspectImage(imageDigest, platform, expected, layerArchiveBytes = expected?.layerArchiveBytes ?? 0, reviewOptions = {}) {
    const proof = await exportOciFilesystem({ imageDigest, platform, archiveBudget: OCI_RUNTIME_LIMITS.archiveBytes - layerArchiveBytes, ...reviewOptions });
    const { image, filesystem } = proof;
    const runtime = checkedOciConfig({ config: image.Config });
    const entrypoint = resolveOciEntrypoint(filesystem, runtime.argv[0]);
    if (expected && (expected.rootfsDigest !== filesystem.digest || canonicalJson(expected.entrypoint) !== canonicalJson(entrypoint) ||
      canonicalJson(expected.argv) !== canonicalJson(runtime.argv) || expected.workingDirectory !== runtime.workingDirectory ||
      expected.environmentDigest !== runtime.environmentDigest || expected.exportArchiveBytes !== proof.exportArchiveBytes)) throw Error('OCI_IMPORTED_FILESYSTEM_IDENTITY_MISMATCH');
    return { ...proof, entrypoint, ...runtime };
}

export async function importOciRuntime({ root, sourceTreeDigest, platform }) {
  if (!hashPattern.test(sourceTreeDigest)) throw Error('OCI_SOURCE_DIGEST_REQUIRED');
  if (process.platform !== 'linux') return { phase: 'NOT_RUN', status: 'INCONCLUSIVE', ready: false, issues: ['OCI_LINUX_DOCKER_REQUIRED'] };
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-oci-import-'));
  const snapshot = join(workspace, 'source'), pack = join(workspace, 'pack');
  const runtimeTag = `mcpshield-oci-${randomUUID()}:local`;
  let ownsImage = false, success = false, stage = 'SOURCE';
  try {
    const sourceSnapshot = await copyFixtureSnapshot(root, snapshot, { profile: OCI_SOURCE_BUDGET_PROFILE });
    if (await artifactDigest(snapshot, { profile: OCI_SOURCE_BUDGET_PROFILE }) !== sourceTreeDigest) throw Error('OCI_SOURCE_DIGEST_MISMATCH');
    const layout = join(snapshot, 'oci'), indexBytes = await readFile(join(layout, 'index.json'));
    const layoutBytes = await readFile(join(layout, 'oci-layout'));
    if (indexBytes.length > 1024 * 1024 || layoutBytes.length > 1024 * 1024) throw Error('OCI_JSON_SIZE_LIMIT');
    if (JSON.parse(layoutBytes).imageLayoutVersion !== '1.0.0') throw Error('OCI_LAYOUT_UNSUPPORTED');
    const index = JSON.parse(indexBytes), blobs = new Map();
    const inspected = await inspectOciImage({ index, platform, budgetProfile: OCI_SOURCE_BUDGET_PROFILE, readBlob: async (entry) => {
      const bytes = await readFile(join(layout, 'blobs', 'sha256', entry.digest.slice(7))); blobs.set(entry.digest, bytes); return bytes;
    } });
    const manifestBytes = index.manifests ? blobs.get(inspected.imageDigest) : indexBytes;
    const manifestDigest = ociHash(manifestBytes), configDigest = inspected.manifest.config.digest;
    const runtime = checkedOciConfig(inspected.config);
    const expansion = inspectOciLayerBudget(inspected.layers.map((layer) => ({ ...layer, bytes: blobs.get(layer.digest) })), inspected.config);
    stage = 'ENGINE';
    let present = false;
    try { present = JSON.parse(await runRuntimeDocker(['image', 'inspect', configDigest, '--format', '{{json .}}'], 5000)).Id === configDigest; }
    catch { /* image may be absent; native load below must independently succeed */ }
    if (!present) {
      await mkdir(join(pack, 'blobs', 'sha256'), { recursive: true });
      // Never import candidate-controlled tag annotations or unrelated manifests.
      // Only this unique owned name may be created by Docker load.
      await writeFile(join(pack, 'oci-layout'), '{"imageLayoutVersion":"1.0.0"}');
      await writeFile(join(pack, 'index.json'), canonicalJson({ schemaVersion: 2, manifests: [{
        mediaType: inspected.manifest.mediaType ?? 'application/vnd.oci.image.manifest.v1+json', digest: manifestDigest, size: manifestBytes.length,
        platform: inspected.platform, annotations: { 'org.opencontainers.image.ref.name': runtimeTag } }] }));
      // Docker-save metadata for the classic native loader; original verified
      // config/compressed layers remain unchanged. Docker applies every layer.
      await writeFile(join(pack, 'manifest.json'), canonicalJson([{ Config: `blobs/sha256/${configDigest.slice(7)}`,
        RepoTags: [runtimeTag], Layers: inspected.layers.map((layer) => `blobs/sha256/${layer.digest.slice(7)}`) }]));
      for (const [digest, bytes] of [[manifestDigest, manifestBytes], [configDigest, blobs.get(configDigest)],
        ...inspected.layers.map((layer) => [layer.digest, blobs.get(layer.digest)])]) {
        await writeFile(join(pack, 'blobs', 'sha256', digest.slice(7)), bytes);
      }
      const archive = join(workspace, 'image.tar');
      await tar.c({ cwd: pack, file: archive, portable: true }, ['oci-layout', 'index.json', 'manifest.json', 'blobs']);
      stage = 'NATIVE_LOAD';
      await runRuntimeDocker(['image', 'load', '--quiet', '--input', archive], 60_000);
      // Not every Docker engine supports OCI layout archives. Failure never
      // falls back to running a foreign importer or a candidate command on host.
      await runRuntimeDocker(['image', 'tag', configDigest, runtimeTag], 5000);
      ownsImage = true;
    }
    stage = 'FINAL_FILESYSTEM';
    const proof = await inspectImage(configDigest, inspected.platform, undefined, expansion.expandedArchiveBytes);
    if (canonicalJson(proof.image.RootFS?.Layers) !== canonicalJson(inspected.config.rootfs.diff_ids) ||
      canonicalJson(proof.argv) !== canonicalJson(runtime.argv) || proof.environmentDigest !== runtime.environmentDigest ||
      proof.workingDirectory !== runtime.workingDirectory) throw Error('OCI_LOADED_CONFIG_MISMATCH');
    const descriptor = { schemaVersion: 'mcpshield.oci-runtime.v1', profile: 'oci-container-v1', stage: 'IMPORTED',
      budgetProfile: OCI_SOURCE_BUDGET_PROFILE, sourceBytes: sourceSnapshot.bytes,
      layerArchiveBytes: expansion.expandedArchiveBytes, exportArchiveBytes: proof.exportArchiveBytes,
      sourceTreeDigest, sourceIndexDigest: ociHash(indexBytes), manifestDigest, configDigest,
      platform: inspected.platform, finalImageDigest: configDigest, imageDigestKind: 'DOCKER_IMAGE_CONFIG_ID',
      rootfsDigest: proof.filesystem.digest, entrypoint: proof.entrypoint, ...runtime, toolSurfaceHash: null, policy: OCI_OBSERVATION_POLICY };
    const descriptorDigest = hashOciRuntimeDescriptor(descriptor);
    success = true;
    return { phase: 'IMPORTED', status: 'INCONCLUSIVE', ready: false, candidateExecutionPerformed: false, issues: [],
      descriptor, descriptorDigest, expansion, runtimeTag: ownsImage ? runtimeTag : null,
      filesystem: { digest: proof.filesystem.digest, algorithm: proof.filesystem.algorithm, files: proof.filesystem.entries.length, bytes: proof.filesystem.bytes },
      cleanup: async () => { if (ownsImage) await runRuntimeDocker(['image', 'rm', runtimeTag], 5000); } };
  } catch (error) {
    return { phase: 'NOT_RUN', status: 'INCONCLUSIVE', ready: false, candidateExecutionPerformed: false,
      issues: [/^OCI_[A-Z_]+$/.test(error.message) ? error.message : stage === 'NATIVE_LOAD' ? 'OCI_NATIVE_IMPORT_FAILED_OR_UNSUPPORTED' : 'OCI_RUNTIME_IMPORT_FAILED'], diagnostics: { stage } };
  } finally {
    if (!success) { try { await runRuntimeDocker(['image', 'rm', runtimeTag], 5000); } catch { /* own unique tag, never broad prune or force */ } }
    await removeFixtureSnapshot(workspace);
  }
}
