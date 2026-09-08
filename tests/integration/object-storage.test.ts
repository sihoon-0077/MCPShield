import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { createS3EvidenceStore } from '../../packages/object-storage/index.mjs';
import { saveEvidence, loadEvidence, type ControlOptions } from '../../apps/api/src/control-plane.js';

test('object-store evidence remains tenant-encrypted and a corrupted existing object cannot complete a retry', async () => {
  const objects = new Map<string, Buffer>();
  const options: ControlOptions = { credentials: [], artifactPath: 'unused', evidencePath: 'unused', evidenceKey: 'a'.repeat(64),
    evidenceStore: { async put(key, bytes) { if (objects.has(key)) return false; objects.set(key, bytes); return true; },
      async get(key) { return objects.get(key)!; }, close() {} } };
  const bundle = { report: 'synthetic private evidence content' };
  const key = await saveEvidence(options, 'tenant-a', bundle);
  assert.equal(objects.get(key)!.includes(Buffer.from(bundle.report)), false);
  assert.deepEqual(await loadEvidence(options, 'tenant-a', key), bundle);
  await assert.rejects(loadEvidence(options, 'tenant-b', key), /EVIDENCE_INTEGRITY_MISMATCH/);
  assert.equal(await saveEvidence(options, 'tenant-a', bundle), key);
  objects.get(key)![30] ^= 1;
  await assert.rejects(saveEvidence(options, 'tenant-a', bundle), /EVIDENCE_INTEGRITY_MISMATCH/);
  options.evidenceStore!.get = async () => { throw Error('S3_EVIDENCE_UNAVAILABLE'); };
  await assert.rejects(loadEvidence(options, 'tenant-a', key), (error: any) => error.message === 'S3_EVIDENCE_UNAVAILABLE' && error.statusCode === 503);
});

test('official S3 adapter signs requests, uses immutable encrypted keys, and bounds actual response streams', async () => {
  const bytes = Buffer.alloc(64, 7), key = 'a'.repeat(64);
  let stored = false, mode = 'normal', requests = 0;
  const server = createServer(async (request, response) => {
    requests++;
    assert.match(request.headers.authorization ?? '', /^AWS4-HMAC-SHA256 /);
    assert.equal(request.url?.split('?')[0], `/private-test/evidence/aa/${key}.bin`);
    if (request.method === 'PUT') {
      assert.equal(request.headers['if-none-match'], '*');
      assert.equal(request.headers['x-amz-server-side-encryption'], 'AES256');
      const chunks = []; for await (const chunk of request) chunks.push(chunk);
      assert.deepEqual(Buffer.concat(chunks), bytes);
      response.writeHead(stored ? 412 : 200).end(); stored = true; return;
    }
    response.writeHead(200, { 'content-type': 'application/octet-stream' });
    if (mode === 'large') { response.end(Buffer.alloc(1025)); return; }
    if (mode === 'stalled') { response.write(Buffer.alloc(32)); return; }
    response.end(bytes);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const store = createS3EvidenceStore({ bucket: 'private-test', region: 'us-east-1',
    endpoint: `http://127.0.0.1:${address.port}`, allowLoopbackHttp: true, timeoutMs: 500, maxBytes: 1024,
    credentials: { accessKeyId: 'synthetic-test-id', secretAccessKey: 'synthetic-test-secret' } });
  try {
    assert.equal(await store.put(key, bytes), true);
    assert.equal(await store.put(key, bytes), false);
    assert.deepEqual(await store.get(key), bytes);
    mode = 'large'; await assert.rejects(store.get(key), /S3_EVIDENCE_SIZE_INVALID/);
    mode = 'stalled'; await assert.rejects(store.get(key), /S3_EVIDENCE_TIMEOUT/);
    const before = requests;
    await assert.rejects(store.put('../escape', bytes), /S3_KEY_INVALID/);
    assert.equal(requests, before);
    assert.throws(() => createS3EvidenceStore({ bucket: 'private-test', region: 'us-east-1', endpoint: 'http://outside.example' }), /S3_ENDPOINT_INVALID/);
  } finally {
    store.close(); server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
