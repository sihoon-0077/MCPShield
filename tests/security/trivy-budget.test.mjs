import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, open, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { artifactDigest } from '../../services/scanner/src/scanner.mjs';
import { snapshotLimits, copyFixtureSnapshot, removeFixtureSnapshot, TRIVY_DATABASE_BUDGET_PROFILE, OCI_SOURCE_BUDGET_PROFILE } from '../../services/scanner/src/snapshot.mjs';

test('trusted Trivy 2 GiB budget is separate from original candidate/OCI limits and preserves canonical byte hashing', async () => {
  assert.equal(TRIVY_DATABASE_BUDGET_PROFILE, 'trivy-db-2g-v1');
  assert.deepEqual(snapshotLimits(TRIVY_DATABASE_BUDGET_PROFILE), { files: 2, bytes: 2 * 1024 ** 3 });
  assert.equal(snapshotLimits('trivy-db-1g-v1').bytes, 1024 ** 3);
  assert.equal(snapshotLimits().bytes, 16 * 1024 ** 2);
  assert.equal(snapshotLimits(OCI_SOURCE_BUDGET_PROFILE).bytes, 100 * 1024 ** 2);
  const root = await mkdtemp(join(tmpdir(), 'mcpshield-trivy-hash-test-'));
  try {
    await writeFile(join(root, 'metadata.json'), '{}'); await writeFile(join(root, 'trivy.db'), 'synthetic bytes only');
    const actual = await artifactDigest(root, { profile: TRIVY_DATABASE_BUDGET_PROFILE });
    assert.equal(actual, await artifactDigest(root, { profile: 'trivy-db-1g-v1' }));
    assert.equal(actual, await artifactDigest(root));
  } finally { await removeFixtureSnapshot(root); }
});

test('Linux sparse trusted DB above 2 GiB is rejected from stat before content copy/hash allocation', { skip: process.platform !== 'linux' }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'mcpshield-trivy-limit-test-'));
  const target = root + '-snapshot';
  try {
    const handle = await open(join(root, 'trivy.db'), 'wx');
    try { await handle.truncate(2 * 1024 ** 3 + 1); } finally { await handle.close(); }
    await assert.rejects(() => copyFixtureSnapshot(root, target, { profile: TRIVY_DATABASE_BUDGET_PROFILE }), /exceeds .* bytes/);
    await assert.rejects(() => artifactDigest(root, { profile: TRIVY_DATABASE_BUDGET_PROFILE }), /exceeded its byte budget/);
  } finally { await removeFixtureSnapshot(target); await removeFixtureSnapshot(root); }
});
