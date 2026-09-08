import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile, open } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import * as tar from 'tar';
import { canonicalJson } from '../../services/scanner/src/evidence.mjs';
import { createOciRuntimeCatalogue, readOciRuntimeCatalogue, inspectOciCoverage } from '../../services/scanner/src/oci-coverage.mjs';
import { checkedTrivyDatabaseMetadata, readTrivyDatabaseIdentity, assessTrivyDocuments, scanOciWithTrivy, trivyContractDiagnostics } from '../../services/scanner/src/oci-trivy.mjs';
import { reviewOciImage } from '../../services/scanner/src/oci-review.mjs';
import { inspectOciFilesystem, ociHash } from '../../services/resolver/src/oci-runtime-descriptor.mjs';
import { removeFixtureSnapshot } from '../../services/scanner/src/snapshot.mjs';

const platform = { os: 'linux', architecture: 'amd64' }, imageDigest = ociHash('authored test image');
function archive(entries) {
  const chunks = [];
  for (const entry of entries) {
    const bytes = entry.bytes ?? Buffer.alloc(0);
    const header = new tar.Header({ path: entry.path, type: entry.type ?? 'File', mode: entry.mode ?? 0o555,
      uid: entry.uid ?? 0, gid: 0, size: bytes.length, mtime: new Date(1000), ...(entry.linkpath ? { linkpath: entry.linkpath } : {}) });
    header.encode(); chunks.push(header.block, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  return Buffer.concat([...chunks, Buffer.alloc(1024)]);
}
const entries = [{ path: 'bin', type: 'Directory' }, { path: 'bin/runtime', bytes: Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0]) },
  { path: 'bin/sh', type: 'SymbolicLink', linkpath: 'runtime' }, { path: 'bin/hard', type: 'Link', linkpath: 'bin/runtime' }];
const catalogue = createOciRuntimeCatalogue({ baseImageDigest: imageDigest, platform, filesystem: inspectOciFilesystem(archive(entries)) });
const coverage = (input) => inspectOciCoverage(inspectOciFilesystem(archive(input), { retainReviewSources: true, trustedEntries: catalogue.entries }), catalogue);

test('OCI base catalogue binds path, ownership, permission and link structure, not merely matching executable bytes', () => {
  assert.equal(coverage(entries).coverage.trustedRuntimeFiles, 1);
  assert.equal(coverage(entries).coverage.sourceClassificationComplete, true);
  for (const change of [{ path: 'bin/moved' }, { mode: 0o444 }, { uid: 1000 }]) {
    const result = coverage(entries.map((entry) => entry.path === 'bin/runtime' ? { ...entry, ...change } : entry));
    assert.equal(result.coverage.trustedRuntimeFiles, 0);
    assert.equal(result.coverage.unknownBinaryFiles, 1);
    assert.equal(result.coverage.sourceClassificationComplete, false);
  }
  for (const [target, change] of [['bin', { mode: 0o777 }], ['bin/sh', { linkpath: '/app/unreviewed' }],
    ['bin/hard', { linkpath: 'app/unreviewed' }]]) {
    const result = coverage(entries.map((entry) => entry.path === target ? { ...entry, ...change } : entry));
    assert.equal(result.coverage.unsupportedEntries, 1);
    assert.ok(result.classifications.some((item) => item.path === target && item.kind === 'UNREVIEWED_FILESYSTEM_STRUCTURE_OR_PRIVILEGE'));
  }
  assert.equal(coverage([...entries, { path: 'app', type: 'Directory' }]).coverage.unsupportedEntries, 1);
  assert.equal(coverage(entries.map((entry) => entry.path === 'bin/runtime' ? { ...entry, mode: 0o4555 } : entry)).coverage.unsupportedEntries, 1);
  const duplicate = [...catalogue.entries, catalogue.entries[0]];
  assert.throws(() => createOciRuntimeCatalogue({ baseImageDigest: imageDigest, platform,
    filesystem: { entries: duplicate, digest: ociHash(canonicalJson(duplicate)) } }), /INVENTORY_INVALID/);
});

test('OCI text classification preserves original byte proof and never claims semantic approval; binaries and omitted sources remain incomplete', () => {
  const input = [...entries, { path: 'server.py', bytes: Buffer.from('print("synthetic inert source")\n') }];
  const result = coverage(input);
  assert.equal(result.coverage.reviewableTextFiles, 1);
  assert.equal(result.coverage.semanticReview, 'NOT_RUN');
  assert.equal(result.coverage.filesystemObservation, 'STATIC_IMAGE_INVENTORY_NOT_SYSCALL_TRACE');
  const filesystem = inspectOciFilesystem(archive(input), { retainReviewSources: true, trustedEntries: catalogue.entries });
  filesystem.reviewSources[0].bytes = Buffer.from('tampered');
  assert.throws(() => inspectOciCoverage(filesystem, catalogue), /SOURCE_HASH_MISMATCH/);
  assert.equal(coverage([...entries, { path: 'opaque.pyc', bytes: Buffer.from('looks like text') }]).coverage.unknownBinaryFiles, 1);
  const bounded = coverage([...entries, { path: 'large.txt', bytes: Buffer.alloc(8 * 1024 * 1024 + 1, 65) }]);
  assert.equal(bounded.coverage.omittedSourceFiles, 1);
  assert.equal(bounded.coverage.sourceClassificationComplete, false);
});

const now = Date.now();
const metadata = { Version: 2, UpdatedAt: new Date(now - 1000).toISOString(), NextUpdate: new Date(now + 3600_000).toISOString() };
test('trusted Trivy DB uses a fixed stable two-file snapshot, fresh metadata, bounded reads and cancellation', async () => {
  const root = await mkdtemp(join(tmpdir(), 'mcpshield-oci-db-test-')), db = join(root, 'db');
  try {
    await mkdir(db);
    await writeFile(join(db, 'metadata.json'), JSON.stringify(metadata));
    await writeFile(join(db, 'trivy.db'), 'synthetic database bytes: never handed to a real scanner');
    const identity = await readTrivyDatabaseIdentity({ databaseDir: db });
    assert.match(identity.databaseDigest, /^sha256:[a-f0-9]{64}$/);
    assert.equal(identity.snapshotDir, undefined);
    assert.equal((await readTrivyDatabaseIdentity({ databaseDir: db })).databaseDigest, identity.databaseDigest);
    await writeFile(join(db, 'trivy.db'), 'different synthetic bytes');
    assert.notEqual((await readTrivyDatabaseIdentity({ databaseDir: db })).databaseDigest, identity.databaseDigest);
    const signal = AbortSignal.abort();
    await assert.rejects(() => readTrivyDatabaseIdentity({ databaseDir: db, signal }), { name: 'AbortError' });
    const handle = await open(join(db, 'metadata.json'), 'w');
    try { await handle.truncate(64 * 1024 + 1); } finally { await handle.close(); }
    await assert.rejects(() => readTrivyDatabaseIdentity({ databaseDir: db }), /METADATA_LIMIT/);
    await writeFile(join(db, 'extra-file'), 'not allowed');
    await assert.rejects(() => readTrivyDatabaseIdentity({ databaseDir: db }), /LAYOUT_INVALID/);
    for (const invalid of [{ ...metadata, Version: 1 }, { ...metadata, UpdatedAt: new Date(now - 25 * 3600_000).toISOString() },
      { ...metadata, UpdatedAt: new Date(now + 3600_000).toISOString() }, { ...metadata, NextUpdate: 'invalid' }]) {
      assert.throws(() => checkedTrivyDatabaseMetadata(invalid, now), /STALE_OR_INVALID/);
    }
  } finally { await removeFixtureSnapshot(root); }
});

const packageReport = () => ({ SchemaVersion: 2, ArtifactType: 'container_image', Metadata: { ImageID: imageDigest, OS: { Family: 'alpine' } },
  Results: [{ Target: 'synthetic', Packages: [{ Name: 'busybox', Version: '1.0.0' }, { Name: '@scope/example', Version: '2.0.0' }] }] });
const sbom = () => ({ bomFormat: 'CycloneDX', specVersion: '1.6', components: [
  { name: 'busybox', version: '1.0.0' }, { group: '@scope', name: 'example', version: '2.0.0' }] });
test('Trivy reports require exact image and complete detected-package CycloneDX coverage, and expose HIGH/CRITICAL without suppression', () => {
  assert.equal(assessTrivyDocuments(packageReport(), sbom(), imageDigest).status, 'COMPLETE');
  const missing = sbom(); missing.components.pop();
  assert.equal(assessTrivyDocuments(packageReport(), missing, imageDigest).status, 'INCONCLUSIVE');
  const noPackages = packageReport(); noPackages.Results[0].Packages = [];
  assert.equal(assessTrivyDocuments(noPackages, sbom(), imageDigest).packageListComplete, false);
  const risky = packageReport(); risky.Results[0].Vulnerabilities = [{ VulnerabilityID: 'SYNTHETIC-CVE-ONLY', Severity: 'HIGH' }];
  assert.equal(assessTrivyDocuments(risky, sbom(), imageDigest).highCriticalCount, 1);
  assert.equal(assessTrivyDocuments(risky, sbom(), imageDigest).status, 'INCONCLUSIVE');
  const eol = packageReport(); eol.Metadata.OS.EOSL = true;
  assert.ok(assessTrivyDocuments(eol, sbom(), imageDigest).issues.includes('OCI_TRIVY_OS_END_OF_LIFE'));
  assert.throws(() => assessTrivyDocuments(packageReport(), sbom(), ociHash('wrong')), /IDENTITY_INVALID/);
  const invalid = packageReport(); invalid.Results[0].Packages = { Name: 'fake', Version: '1' };
  assert.throws(() => assessTrivyDocuments(invalid, sbom(), imageDigest), /REPORT_INVALID/);
});

test('CycloneDX 1.4 through native Trivy 1.7 retain exact component coverage; unknown versions and malformed fields fail closed', () => {
  for (const specVersion of ['1.4', '1.5', '1.6', '1.7']) {
    assert.equal(assessTrivyDocuments(packageReport(), { ...sbom(), specVersion }, imageDigest).status, 'COMPLETE');
  }
  for (const specVersion of ['1.3', '1.8', '2.0', '', 1.7, null]) {
    assert.throws(() => assessTrivyDocuments(packageReport(), { ...sbom(), specVersion }, imageDigest), /IDENTITY_INVALID/);
  }
  for (const invalid of [{ name: 1 }, { group: [] }, { version: 1 }]) {
    const bom = { ...sbom(), specVersion: '1.7' };
    Object.assign(bom.components[0], invalid);
    assert.throws(() => assessTrivyDocuments(packageReport(), bom, imageDigest), /REPORT_INVALID/);
  }
  const bom = { ...sbom(), specVersion: '1.7' };
  delete bom.components[0].version;
  bom.components[0].versionRange = 'vers:generic/>=1.0.0';
  assert.equal(assessTrivyDocuments(packageReport(), bom, imageDigest).packageListComplete, false);
});

test('OCI review failure never becomes READY or reuses npm approval', async () => {
  const result = await reviewOciImage({ descriptor: {}, expectedDescriptorDigest: imageDigest, trust: {} });
  assert.equal(result.status, 'INCONCLUSIVE'); assert.equal(result.approvalVerdict, 'ABSTAIN');
  assert.equal(result.ready, false); assert.equal(result.candidateExecutionPerformed, false);
  assert.equal(result.privateEvidence, null);
  assert.ok(result.pendingChecks.includes('VALIDATOR_INDEPENDENT_REPLAY'));
});

test('native Trivy contract diagnostics expose shapes/counts/numeric versions but never raw private metadata', () => {
  const report = packageReport(), bom = sbom();
  assert.deepEqual(trivyContractDiagnostics(report, bom, imageDigest), {
    reportSchemaVersion: 2, reportArtifactType: 'container_image', reportImageIdMatches: true,
    reportResultsShape: 'ARRAY', reportResultsCount: 1, sbomFormat: 'CycloneDX', sbomSpecVersion: '1.6',
    sbomComponentsShape: 'ARRAY', sbomComponentsCount: 2 });
  const sentinel = 'PRIVATE_SOURCE_OR_CREDENTIAL';
  const diagnostic = trivyContractDiagnostics({ SchemaVersion: sentinel, ArtifactType: sentinel, Results: sentinel },
    { bomFormat: sentinel, specVersion: sentinel, components: sentinel }, imageDigest);
  assert.equal(JSON.stringify(diagnostic).includes(sentinel), false);
  assert.equal(diagnostic.sbomComponentsShape, 'OTHER');
});

test('actual Linux approved image catalogue, offline Trivy vulnerability scan and native CycloneDX conversion', {
  skip: process.env.MCPSHIELD_DOCKER_TESTS !== '1' || !process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE ||
    !process.env.MCPSHIELD_TRIVY_IMAGE || !process.env.MCPSHIELD_TRIVY_DATABASE_DIR, timeout: 240_000,
}, async () => {
  const baseImageDigest = process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE;
  const live = await readOciRuntimeCatalogue({ baseImageDigest, platform });
  assert.equal(live.source, 'LIVE_DOCKER_EXPORT');
  assert.ok(live.entries.length > 10);
  const databaseDir = process.env.MCPSHIELD_TRIVY_DATABASE_DIR;
  const database = await readTrivyDatabaseIdentity({ databaseDir });
  const result = await scanOciWithTrivy({ imageDigest: baseImageDigest, baseImageDigest, platform,
    trust: { trivyImageDigest: process.env.MCPSHIELD_TRIVY_IMAGE, databaseDir, databaseDigest: database.databaseDigest } });
  const safe = JSON.stringify({ status: result.status, issues: result.issues, diagnostics: result.diagnostics,
    images: result.images?.map(({ packages, components, packageListComplete, highCriticalCount }) => ({ packages, components, packageListComplete, highCriticalCount })) });
  assert.equal(result.status, 'COMPLETE', safe);
  assert.equal(result.images.length, 1); assert.equal(result.highCriticalCount, 0);
  assert.ok(result.images[0].packageListComplete);
  assert.equal(result.isolation.candidateExecutionPerformed, false);
  assert.equal(result.isolation.dockerSocket, 'ABSENT');
  assert.equal(result.privateEvidence.access, 'ENCRYPTED_OPERATOR_EVIDENCE_ONLY');
});
