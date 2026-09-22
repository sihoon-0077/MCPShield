import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { registryMetadataTarget, startRegistryBroker } from '../../services/resolver/src/registry-broker.mjs';

const token = 'a'.repeat(48);
const metadata = { name: 'fixture', 'dist-tags': { latest: '1.0.0' }, versions: { '1.0.0': { name: 'fixture', version: '1.0.0' } } };

test('metadata broker accepts only canonical registry package paths, never arbitrary URLs/tarballs/control characters', () => {
  assert.deepEqual(registryMetadataTarget('/fixture'), { name: 'fixture', url: 'https://registry.npmjs.org/fixture' });
  assert.deepEqual(registryMetadataTarget('/@scope%2fname'), { name: '@scope/name', url: 'https://registry.npmjs.org/@scope%2Fname' });
  for (const path of ['https://example.test/', '//example.test/', '/fixture/-/fixture.tgz', '/fixture?token=private',
    '/%2e%2e/private', '/@scope%2fname%2fother', '/file%00name', '/fixture#fragment', '/fixture\\other', '/http:%2f%2fprivate']) {
    assert.throws(() => registryMetadataTarget(path), /PATH_INVALID/);
  }
});

test('broker isolates credentials, bounds metadata responses and emits only digest provenance', async () => {
  const upstream = [];
  const broker = await startRegistryBroker({ token, fetchMetadata: async (url, options) => {
    upstream.push({ url, options });
    return new Response(JSON.stringify(metadata), { headers: { 'content-type': 'application/json' } });
  } });
  const auth = { authorization: `Bearer ${token}` };
  try {
    assert.equal((await fetch(`${broker.url}/fixture`)).status, 401);
    assert.equal((await fetch(`${broker.url}/fixture`, { method: 'POST', headers: auth, body: 'never forwarded' })).status, 405);
    assert.equal((await fetch(`${broker.url}/fixture/-/fixture.tgz`, { headers: auth })).status, 502);
    assert.deepEqual(await (await fetch(`${broker.url}/fixture`, { headers: auth })).json(), metadata);
    assert.deepEqual(await (await fetch(`${broker.url}/fixture`, { headers: auth })).json(), metadata);
    assert.equal(upstream.length, 1);
    assert.equal(upstream[0].url, 'https://registry.npmjs.org/fixture');
    assert.equal(upstream[0].options.redirect, 'error');
    assert.deepEqual(upstream[0].options.headers, { accept: 'application/vnd.npm.install-v1+json' });
    const evidence = await (await fetch(`${broker.url}/__evidence`, { headers: auth })).json();
    assert.equal(evidence.source, 'OFFICIAL_REGISTRY_HTTPS');
    assert.equal(evidence.metadataOnly, true);
    assert.equal(evidence.records.length, 1);
    assert.equal(JSON.stringify(evidence).includes(token), false);
    assert.equal(JSON.stringify(evidence).includes('fixture'), false);
  } finally { await broker.close(); }
  const oversized = await startRegistryBroker({ token, fetchMetadata: async () => new Response(Buffer.alloc(4 * 1024 * 1024 + 1)) });
  try {
    const response = await fetch(`${oversized.url}/fixture`, { headers: auth });
    assert.equal(response.status, 502);
    assert.equal(oversized.evidence().records.length, 0);
    assert.equal(oversized.evidence().totalBytes, 0);
  } finally { await oversized.close(); }
});

test('synthetic broker fixture mode is explicit and never invokes an external fetch', async () => {
  const broker = await startRegistryBroker({ token, metadataFixture: { fixture: metadata }, fetchMetadata: async () => { throw Error('MUST_NOT_FETCH'); } });
  try {
    assert.equal((await fetch(`${broker.url}/fixture`, { headers: { authorization: `Bearer ${token}` } })).status, 200);
    assert.equal(broker.evidence().source, 'SYNTHETIC_METADATA_FIXTURE');
    assert.equal((await fetch(`${broker.url}/missing`, { headers: { authorization: `Bearer ${token}` } })).status, 404);
  } finally { await broker.close(); }
});

test('metadata body timeout aborts an actual stalled HTTP response without retaining private body text', { timeout: 15_000 }, async () => {
  const upstream = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.write('{"private":"SYNTHETIC_NEVER_LOG');
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const broker = await startRegistryBroker({ token, fetchMetadata: (_url, options) => fetch(`http://127.0.0.1:${upstream.address().port}`, options) });
  try {
    const started = Date.now();
    const response = await fetch(`${broker.url}/fixture`, { headers: { authorization: `Bearer ${token}` } });
    assert.equal(response.status, 502);
    assert.deepEqual(await response.json(), { error: 'REGISTRY_TIMEOUT_OR_SIZE_LIMIT' });
    assert.ok(Date.now() - started < 12_000);
    assert.equal(broker.evidence().records.length, 0);
    assert.equal(broker.evidence().totalBytes, 0);
    assert.equal(JSON.stringify(broker.evidence()).includes('SYNTHETIC_NEVER_LOG'), false);
  } finally {
    await broker.close();
    upstream.closeAllConnections();
    await new Promise((resolve) => upstream.close(resolve));
  }
});
