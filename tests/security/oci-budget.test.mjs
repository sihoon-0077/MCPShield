import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, open, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { createGzip } from 'node:zlib';
import * as tar from 'tar';
import { artifactDigest } from '../../services/scanner/src/scanner.mjs';
import { copyFixtureSnapshot, removeFixtureSnapshot, snapshotLimits, OCI_SOURCE_BUDGET_PROFILE } from '../../services/scanner/src/snapshot.mjs';
import { inspectOciImage } from '../../services/resolver/src/oci.mjs';
import { inspectOciFilesystem, ociHash } from '../../services/resolver/src/oci-runtime-descriptor.mjs';
import { inspectOciLayerBudget } from '../../services/resolver/src/oci-runtime.mjs';

test('named OCI budget accepts actual >16 MiB bytes with unchanged hash encoding; legacy and >100 MiB still reject', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-oci-budget-'));
  try {
    const source = join(workspace, 'source'); await mkdir(source);
    const bytes = Buffer.alloc(17 * 1024 * 1024, 71);
    await writeFile(join(source, 'data.bin'), bytes);
    const expected = `sha256:${createHash('sha256').update('data.bin\0').update(bytes).update('\0').digest('hex')}`;
    await assert.rejects(() => copyFixtureSnapshot(source, join(workspace, 'legacy')), /byte|exceed/);
    await assert.rejects(() => artifactDigest(source), /byte|exceed/);
    const snapshot = await copyFixtureSnapshot(source, join(workspace, 'large'), { profile: OCI_SOURCE_BUDGET_PROFILE });
    assert.equal(snapshot.bytes, bytes.length);
    assert.equal(await artifactDigest(snapshot.root, { profile: OCI_SOURCE_BUDGET_PROFILE }), expected);
    assert.throws(() => snapshotLimits('arbitrary-client-budget'), /BUDGET_PROFILE/);
    const sparse = await open(join(source, 'data.bin'), 'r+');
    try { await sparse.truncate(100 * 1024 * 1024 + 1); } finally { await sparse.close(); }
    await assert.rejects(() => copyFixtureSnapshot(source, join(workspace, 'over'), { profile: OCI_SOURCE_BUDGET_PROFILE }), /byte|exceed/);
    await assert.rejects(() => artifactDigest(source, { profile: OCI_SOURCE_BUDGET_PROFILE }), /byte|exceed/);
  } finally { await removeFixtureSnapshot(workspace); }
});

test('OCI JSON, source declaration and expanded tar entry limits reject before unbounded processing', async () => {
  await assert.rejects(() => inspectOciImage({ index: { padding: 'x'.repeat(1024 * 1024) }, readBlob: () => { throw Error('must not read'); },
    budgetProfile: OCI_SOURCE_BUDGET_PROFILE }), /JSON_SIZE_LIMIT/);
  await assert.rejects(() => inspectOciImage({ index: { schemaVersion: 2, config: { digest: ociHash('x'), size: 1024 * 1024 + 1 }, layers: [] },
    readBlob: () => { throw Error('must not read'); }, budgetProfile: OCI_SOURCE_BUDGET_PROFILE }), /oversized OCI descriptor/);
  const header = new tar.Header({ path: 'oversized', type: 'File', mode: 0o444, uid: 0, gid: 0, size: 512 * 1024 * 1024 + 1 }); header.encode();
  assert.throws(() => inspectOciFilesystem(Buffer.concat([header.block, Buffer.alloc(1024)])), /FILESYSTEM_ENTRY_INVALID/);
  const entries = [];
  for (let index = 0; index <= 50_000; index++) {
    const item = new tar.Header({ path: `entry-${index}`, type: 'File', mode: 0o444, uid: 0, gid: 0, size: 0 }); item.encode(); entries.push(item.block);
  }
  assert.throws(() => inspectOciFilesystem(Buffer.concat([...entries, Buffer.alloc(1024)])), /FILESYSTEM_ENTRY_INVALID/);
});

test('actual gzip expansion beyond the fixed 512 MiB budget is refused before OCI import (opt-in memory acceptance)', {
  skip: process.env.MCPSHIELD_OCI_100M_TESTS !== '1', timeout: 120_000,
}, async () => {
  // Compress in 64 KiB chunks so the fixture itself never holds a 513 MiB raw
  // allocation. The bounded native inflater must stop at its fixed output cap.
  const gzip = createGzip(), chunks = [], hash = createHash('sha256');
  gzip.on('data', (chunk) => chunks.push(chunk));
  const ended = once(gzip, 'end'), chunk = Buffer.alloc(64 * 1024);
  for (let offset = 0; offset < 513 * 1024 * 1024; offset += chunk.length) {
    hash.update(chunk);
    if (!gzip.write(chunk)) await once(gzip, 'drain');
  }
  gzip.end(); await ended;
  assert.throws(() => inspectOciLayerBudget([{ bytes: Buffer.concat(chunks), mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip' }],
    { rootfs: { type: 'layers', diff_ids: [`sha256:${hash.digest('hex')}`] } }), /LAYER_EXPANSION_FAILED/);
});
