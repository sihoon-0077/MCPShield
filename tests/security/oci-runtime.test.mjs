import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { createServer } from 'node:http';
import * as tar from 'tar';
import { checkedOciConfig, hashOciRuntimeDescriptor, inspectOciFilesystem, resolveOciEntrypoint,
  ociHash, OCI_OBSERVATION_POLICY, OCI_SOURCE_BUDGET_PROFILE } from '../../services/resolver/src/oci-runtime-descriptor.mjs';
import { inspectOciLayerBudget, importOciRuntime, inspectImportedOciRuntime } from '../../services/resolver/src/oci-runtime.mjs';
import { collectOciMcp, observeOciRuntime } from '../../services/scanner/src/oci-observer.mjs';
import { runRuntimeDocker } from '../../services/resolver/src/npm-closure.mjs';
import { removeFixtureSnapshot } from '../../services/scanner/src/snapshot.mjs';
import { artifactDigest } from '../../services/scanner/src/scanner.mjs';
import { verifyEvidenceBundle } from '../../services/scanner/src/evidence.mjs';
import { scanOciRuntime } from '../../services/scanner/src/oci-scan.mjs';
import { readTrivyDatabaseIdentity } from '../../services/scanner/src/oci-trivy.mjs';
import { validateOciReleaseBinding } from '../../services/scanner/src/oci-binding.mjs';
import { reconstructOciSemanticSources, verifyOciSemanticReview } from '../../services/scanner/src/oci-sources.mjs';

const platform = { os: 'linux', architecture: 'amd64' };
function archive(entries, mtime = 1) {
  const chunks = [];
  for (const entry of entries) {
    const bytes = entry.bytes ?? Buffer.alloc(0);
    const header = new tar.Header({ path: entry.path, type: entry.type ?? 'File', mode: entry.mode ?? 0o555,
      uid: 0, gid: 0, size: bytes.length, mtime: new Date(mtime * 1000), ...(entry.linkpath ? { linkpath: entry.linkpath } : {}) });
    header.encode(); chunks.push(header.block, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  return Buffer.concat([...chunks, Buffer.alloc(1024)]);
}
const basicEntries = [{ path: 'bin', type: 'Directory' }, { path: 'bin/runner', bytes: Buffer.from('opaque synthetic binary, never execute') },
  { path: 'bin/sh', type: 'SymbolicLink', linkpath: 'runner' }];
const runtime = { argv: ['/bin/sh', '/server.sh'], workingDirectory: '/', environmentDigest: ociHash('[]') };
function descriptor() {
  const filesystem = inspectOciFilesystem(archive(basicEntries)), digest = ociHash('config');
  return { schemaVersion: 'mcpshield.oci-runtime.v1', profile: 'oci-container-v1', stage: 'IMPORTED',
    budgetProfile: OCI_SOURCE_BUDGET_PROFILE, sourceBytes: 10000, layerArchiveBytes: 4096, exportArchiveBytes: 4096,
    sourceTreeDigest: ociHash('source'), sourceIndexDigest: ociHash('index'), manifestDigest: ociHash('manifest'), configDigest: digest,
    platform, finalImageDigest: digest, imageDigestKind: 'DOCKER_IMAGE_CONFIG_ID', rootfsDigest: filesystem.digest,
    entrypoint: resolveOciEntrypoint(filesystem, '/bin/sh'), ...runtime, toolSurfaceHash: null, policy: OCI_OBSERVATION_POLICY };
}

test('OCI runtime descriptor is a separate non-approval identity with canonical final filesystem and link-chain binding', () => {
  const first = inspectOciFilesystem(archive(basicEntries));
  assert.equal(first.digest, inspectOciFilesystem(archive([...basicEntries].reverse(), 123)).digest);
  assert.notEqual(first.digest, inspectOciFilesystem(archive(basicEntries.map((entry) => entry.path === 'bin/runner' ? { ...entry, bytes: Buffer.from('different') } : entry))).digest);
  assert.equal(resolveOciEntrypoint(first, '/bin/sh').resolvedPath, '/bin/runner');
  const original = descriptor(), hash = hashOciRuntimeDescriptor(original);
  for (const field of ['sourceTreeDigest', 'sourceIndexDigest', 'manifestDigest', 'rootfsDigest', 'environmentDigest']) {
    assert.notEqual(hashOciRuntimeDescriptor({ ...original, [field]: ociHash('changed') }), hash);
  }
  for (const change of [{ stage: 'READY' }, { toolSurfaceHash: '0x' + '1'.repeat(64) }, { profile: 'npm-closure-v1' },
    { policy: { ...original.policy, binarySemantic: 'REVIEWED' } }, { finalImageDigest: ociHash('other') }, { unknown: true },
    { budgetProfile: 'unlimited' }, { sourceBytes: 100 * 1024 * 1024 + 1 }, { layerArchiveBytes: 512 * 1024 * 1024 },
    { exportArchiveBytes: 0 }, { sourceBytes: 1.5 }]) {
    assert.throws(() => hashOciRuntimeDescriptor({ ...original, ...change }), /OCI_/);
  }
  assert.throws(() => resolveOciEntrypoint(inspectOciFilesystem(archive([
    { path: 'a', type: 'SymbolicLink', linkpath: 'b' }, { path: 'b', type: 'SymbolicLink', linkpath: 'a' }])), '/a'), /LINK_CYCLE/);
  assert.throws(() => inspectOciFilesystem(archive([{ path: '../outside' }])), /ENTRY_INVALID/);
  assert.throws(() => inspectOciFilesystem(archive([...basicEntries, basicEntries[1]])), /ENTRY_INVALID/);
});

test('OCI image config rejects dynamic environment, inferred PATH entrypoints and mutable volumes before any execution', async () => {
  assert.deepEqual(checkedOciConfig({ config: { Entrypoint: ['/bin/sh'], Cmd: ['/server.sh'], Env: ['PATH=/bin', 'LANG=C.UTF-8'] } }).argv, runtime.argv);
  for (const Env of [['LD_PRELOAD=/app/foreign.so'], ['NODE_OPTIONS=--require=/app/foreign'], ['PYTHONPATH=/app'], ['PATH=.:/bin'],
    ['HOME=/private'], ['DEMO_TOKEN=not-public'], ['LANG=C', 'LANG=UTF-8']]) {
    assert.throws(() => checkedOciConfig({ config: { Cmd: ['/bin/sh'], Env } }), /ENVIRONMENT/);
  }
  assert.throws(() => checkedOciConfig({ config: { Cmd: ['python', 'server.py'] } }), /ABSOLUTE_ENTRYPOINT/);
  assert.throws(() => checkedOciConfig({ config: { Cmd: ['/bin/sh'], Volumes: { '/app': {} } } }), /MUTABLE/);
  await assert.rejects(() => collectOciMcp({ container: 'arbitrary-candidate-command', timeoutMs: 1000 }), /CONTAINER_INVALID/);
});

test('OCI layers verify native diff IDs and decompression bounds without applying whiteouts or extracting files', () => {
  const layer = archive([...basicEntries, { path: '.wh.removed', bytes: Buffer.alloc(0), mode: 0 }]);
  const config = { rootfs: { type: 'layers', diff_ids: [ociHash(layer)] } };
  assert.equal(inspectOciLayerBudget([{ bytes: gzipSync(layer), mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip' }], config).appliedBy, 'NATIVE_DOCKER_ONLY');
  assert.throws(() => inspectOciLayerBudget([{ bytes: gzipSync(layer), mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip' }],
    { rootfs: { type: 'layers', diff_ids: [ociHash('wrong')] } }), /DIFF_ID/);
  assert.throws(() => inspectOciLayerBudget([{ bytes: layer, mediaType: 'foreign-compression' }], config), /MEDIA_UNSUPPORTED/);
});

async function copiedFile(container, path) {
  const files = [];
  const listing = tar.t({ strict: true, sync: true, onReadEntry(entry) {
    assert.equal(entry.type, 'File'); const chunks = [];
    entry.on('data', (bytes) => chunks.push(bytes)); entry.on('end', () => files.push(Buffer.concat(chunks)));
  } });
  listing.end(await runRuntimeDocker(['cp', '-L', container + ':' + path, '-'], 5000, 4 * 1024 * 1024));
  assert.equal(files.length, 1); return files[0];
}

async function actualOciScenario({ sourceTargetBytes = null, fullScan = false } = {}) {
  const builder = process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE;
  const sourceContainer = 'mcpshield-oci-fixture-source-' + randomUUID();
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-oci-runtime-test-'));
  let imported;
  try {
    // Read the existing approved CI builder's native BusyBox/musl bytes through
    // an unstarted container. Never import or run these binaries on the host.
    await runRuntimeDocker(['create', '--pull=never', '--name', sourceContainer, '--entrypoint=/bin/false', builder], 5000);
    const busybox = await copiedFile(sourceContainer, '/bin/busybox');
    const loader = await copiedFile(sourceContainer, '/lib/ld-musl-x86_64.so.1');
    const script = Buffer.from((await readFile('demo/fixtures/oci-stdio/server.sh', 'utf8')).replaceAll('\r\n', '\n'));
    // Seeded native SHAKE bytes are inert data, not an external artifact or code.
    // Uncompressed large acceptance keeps actual source length exactly measurable.
    const padding = createHash('shake256', { outputLength: sourceTargetBytes ? sourceTargetBytes - busybox.length - loader.length - 64 * 1024 : 17 * 1024 * 1024 })
      .update('MCPShield authored synthetic OCI budget fixture v1').digest();
    const layer = archive([{ path: 'bin', type: 'Directory' }, { path: 'lib', type: 'Directory' },
      { path: 'bin/busybox', bytes: busybox }, { path: 'bin/sh', type: 'SymbolicLink', linkpath: 'busybox' },
      { path: 'lib/ld-musl-x86_64.so.1', bytes: loader },
      { path: 'lib/libc.musl-x86_64.so.1', type: 'SymbolicLink', linkpath: 'ld-musl-x86_64.so.1' },
      { path: 'server.sh', bytes: script }, { path: 'synthetic-padding.bin', bytes: padding, mode: 0o444 }]);
    const layerBytes = sourceTargetBytes ? layer : gzipSync(layer), configBytes = Buffer.from(JSON.stringify({ architecture: 'amd64', os: 'linux',
      config: { Entrypoint: ['/bin/sh'], Cmd: ['/server.sh'], WorkingDir: '/', Env: ['PATH=/bin'], User: '1000:1000' },
      rootfs: { type: 'layers', diff_ids: [ociHash(layer)] }, history: [{ created_by: 'AUTHORED_SYNTHETIC_OCI_FIXTURE' }] }));
    const config = { mediaType: 'application/vnd.oci.image.config.v1+json', digest: ociHash(configBytes), size: configBytes.length };
    const layerDescriptor = { mediaType: sourceTargetBytes ? 'application/vnd.oci.image.layer.v1.tar' : 'application/vnd.oci.image.layer.v1.tar+gzip',
      digest: ociHash(layerBytes), size: layerBytes.length };
    const manifestBytes = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json', config, layers: [layerDescriptor] }));
    const oci = join(workspace, 'oci'); await mkdir(join(oci, 'blobs/sha256'), { recursive: true });
    for (const bytes of [configBytes, layerBytes, manifestBytes]) await writeFile(join(oci, 'blobs/sha256', ociHash(bytes).slice(7)), bytes);
    const layout = Buffer.from('{"imageLayoutVersion":"1.0.0"}');
    const index = Buffer.from(JSON.stringify({ schemaVersion: 2, manifests: [{
      mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: ociHash(manifestBytes), size: manifestBytes.length, platform,
      annotations: { 'org.opencontainers.image.ref.name': 'MUST_NOT_IMPORT_THIS_TAG' } }] }));
    await writeFile(join(oci, 'oci-layout'), layout);
    await writeFile(join(oci, 'index.json'), index);
    const sourceBytes = [configBytes, layerBytes, manifestBytes, layout, index].reduce((sum, bytes) => sum + bytes.length, 0);
    if (sourceTargetBytes) {
      // Exact 100 MiB original source: >99 MiB is the actually imported layer;
      // a small inert source record fills tar/header alignment overhead.
      assert.ok(sourceBytes > sourceTargetBytes - 64 * 1024 && sourceBytes < sourceTargetBytes);
      await writeFile(join(workspace, 'acceptance-alignment.bin'), Buffer.alloc(sourceTargetBytes - sourceBytes, 7));
    }
    const original = await artifactDigest(workspace, { profile: OCI_SOURCE_BUDGET_PROFILE });
    imported = await importOciRuntime({ root: workspace, sourceTreeDigest: original, platform });
    assert.deepEqual(imported.issues, [], JSON.stringify({ issues: imported.issues, diagnostics: imported.diagnostics }));
    assert.equal(imported.phase, 'IMPORTED'); assert.equal(imported.ready, false);
    assert.equal(imported.descriptor.budgetProfile, OCI_SOURCE_BUDGET_PROFILE);
    assert.equal(imported.descriptor.sourceBytes, sourceTargetBytes ?? sourceBytes);
    assert.ok(imported.descriptor.sourceBytes > 16 * 1024 * 1024);
    assert.ok(imported.descriptor.layerArchiveBytes + imported.descriptor.exportArchiveBytes <= 512 * 1024 * 1024);
    assert.equal(imported.descriptor.finalImageDigest, config.digest);
    assert.equal(imported.descriptor.entrypoint.resolvedPath, '/bin/busybox');
    for (let repeat = 0; repeat < 2; repeat++) {
      const proof = await inspectImportedOciRuntime({ descriptor: imported.descriptor, expectedDescriptorDigest: imported.descriptorDigest });
      assert.equal(proof.candidateExecutionPerformed, false);
      assert.equal(proof.filesystem.digest, imported.descriptor.rootfsDigest);
      assert.equal(proof.exportArchiveBytes, imported.descriptor.exportArchiveBytes);
    }
    const observed = await observeOciRuntime({ descriptor: imported.descriptor, expectedDescriptorDigest: imported.descriptorDigest, sinkImageDigest: builder,
      probePlan: { scenarios: [
        { scenarioId: 'normal', kind: 'NORMAL', goal: 'Read synthetic message', toolName: 'echo_safe', argumentsJson: '{}' },
        { scenarioId: 'boundary', kind: 'ADVERSARIAL', goal: 'Observe synthetic boundary', toolName: 'leak_canary', argumentsJson: '{}' },
      ] } });
    assert.deepEqual(observed.report.issues, [], JSON.stringify({ issues: observed.report.issues, checks: observed.report.checks, steps: observed.report.steps }));
    assert.equal(observed.report.observationStatus, 'COMPLETED_LIMITED_OCI_PROFILE');
    assert.equal(observed.report.status, 'FAILED');
    assert.equal(observed.report.steps.discovery.mcp.pages, 2);
    assert.equal(observed.report.checks.normalToolCallsSucceeded, true);
    assert.equal(observed.report.checks.adversarialToolCallsSucceeded, true);
    assert.ok(observed.report.findings.some((finding) => finding.code === 'CANARY_EXFILTRATION'));
    assert.equal(observed.report.approvalVerdict, 'ABSTAIN');
    assert.equal(observed.report.binarySemantic, 'NOT_REVIEWED');
    assert.equal(observed.report.filesystemObservation, 'NOT_OBSERVED');
    assert.equal(observed.report.ready, false);
    assert.equal(verifyEvidenceBundle(observed.bundle, observed.bundle.manifest.root), true);
    assert.equal(await artifactDigest(workspace, { profile: OCI_SOURCE_BUDGET_PROFILE }), original);
    if (fullScan) {
      const databaseDir = process.env.MCPSHIELD_TRIVY_DATABASE_DIR;
      const database = await readTrivyDatabaseIdentity({ databaseDir });
      const server = createServer(async (request, response) => {
        for await (const _chunk of request) { /* local authored fixture contract only; never external provider quality */ }
        response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ riskClaims: [],
          semanticDiff: { purposeChanged: false, dataScopeExpanded: false, newHiddenObligation: false }, needsHumanReview: false }));
      });
      await new Promise((done) => server.listen(0, '127.0.0.1', done));
      try {
        const scanned = await scanOciRuntime({ descriptor: imported.descriptor, expectedDescriptorDigest: imported.descriptorDigest,
          sourceReleaseId: '0x' + 'a'.repeat(64), releaseId: 'authored-oci@1.0.0',
          trust: { baseImageDigest: builder, sinkImageDigest: builder, trivyImageDigest: process.env.MCPSHIELD_TRIVY_IMAGE,
            databaseDir, databaseDigest: database.databaseDigest },
          probePlan: { scenarios: [
            { scenarioId: 'normal', kind: 'NORMAL', goal: 'Read synthetic message', toolName: 'echo_safe', argumentsJson: '{}' },
            { scenarioId: 'boundary', kind: 'ADVERSARIAL', goal: 'Observe synthetic boundary', toolName: 'leak_canary', argumentsJson: '{}' },
          ] }, ai: { allowRemoteAi: true, provider: 'custom', disclosurePolicy: 'LOCAL_CONTRACT_TEST',
            url: `http://127.0.0.1:${server.address().port}`, maxBatches: 128, totalTimeoutMs: 300_000 } });
        const safe = JSON.stringify({ analysis: scanned.analysis, resultStatus: scanned.result?.scanStatus });
        assert.ok(scanned.binding && validateOciReleaseBinding(scanned.binding), safe);
        assert.equal(scanned.result.scanStatus, 'FAILED', safe);
        assert.equal(scanned.analysis.verdict, 'ABSTAIN'); assert.equal(scanned.analysis.ready, false);
        assert.ok(scanned.analysis.issues.includes('OCI_INDEPENDENT_SIGNING_POLICY'));
        assert.equal(scanned.analysis.checks.sourceClassificationComplete, false, 'opaque padding/native bytes are never silently approved');
        assert.equal(scanned.analysis.checks.normalToolCallsSucceeded, true, safe);
        assert.equal(scanned.analysis.checks.adversarialToolCallsSucceeded, true, safe);
        assert.equal(verifyEvidenceBundle(scanned.bundle, scanned.bundle.manifest.root), true);
        const privateEvidence = JSON.parse(scanned.bundle.files['oci/private-image-evidence.json']);
        assert.equal(privateEvidence.access, 'ENCRYPTED_OPERATOR_EVIDENCE_ONLY');
        assert.ok(privateEvidence.trivy?.documents?.length > 0, 'actual native Trivy evidence required, not a portable stub');
        const semantic = JSON.parse(scanned.bundle.files['semantic/reviews.json']);
        assert.equal(semantic.disclosure.policy, 'LOCAL_CONTRACT_TEST');
        assert.equal(semantic.disclosure.providerQuality, 'PROVIDER_QUALITY_NOT_MEASURED');
        const reconstructed = reconstructOciSemanticSources(scanned.binding.descriptor, privateEvidence);
        const verified = verifyOciSemanticReview({ semantic, files: reconstructed.files,
          tools: JSON.parse(scanned.bundle.files['runtime/tools.json']), releaseId: 'authored-oci@1.0.0' });
        assert.equal(verified.semanticComplete, true, safe);
        assert.equal(verified.independentCriticComplete, true, safe);
        assert.equal(await artifactDigest(workspace, { profile: OCI_SOURCE_BUDGET_PROFILE }), original);
      } finally { await new Promise((done) => server.close(done)); }
    }
  } finally {
    await imported?.cleanup?.();
    await runRuntimeDocker(['rm', '-f', sourceContainer], 5000).catch(() => {});
    await removeFixtureSnapshot(workspace);
  }
}

test('actual Linux native OCI import and external MCP collector run a non-Node shell image larger than 16 MiB', {
  skip: process.env.MCPSHIELD_DOCKER_TESTS !== '1' || !process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE, timeout: 180_000,
}, () => actualOciScenario());

test('actual Linux 100 MiB original OCI source imports and executes the same restricted MCP observation profile', {
  skip: process.env.MCPSHIELD_DOCKER_TESTS !== '1' || process.env.MCPSHIELD_OCI_100M_TESTS !== '1' ||
    !process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE, timeout: 300_000,
}, () => actualOciScenario({ sourceTargetBytes: 100 * 1024 * 1024 }));

test('actual Linux OCI scan binds native inventory, offline Trivy, local semantic contract and repeated MCP observation without approving omitted binary coverage', {
  skip: process.env.MCPSHIELD_DOCKER_TESTS !== '1' || process.env.MCPSHIELD_OCI_FULLSCAN_TESTS !== '1' ||
    !process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE || !process.env.MCPSHIELD_TRIVY_IMAGE || !process.env.MCPSHIELD_TRIVY_DATABASE_DIR,
  timeout: 600_000,
}, () => actualOciScenario({ fullScan: true }));
