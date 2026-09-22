import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const MAX_RESPONSE = 4 * 1024 * 1024;
const MAX_TOTAL = 32 * 1024 * 1024;
const PACKAGE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

export function registryMetadataTarget(path) {
  if (typeof path !== 'string' || path.length > 512 || !path.startsWith('/') || /[?#\\\x00-\x20\x7f]/.test(path)) throw Error('REGISTRY_METADATA_PATH_INVALID');
  let name;
  try { name = decodeURIComponent(path.slice(1)); } catch { throw Error('REGISTRY_METADATA_PATH_INVALID'); }
  if (!PACKAGE.test(name) || name.includes('..') || name.endsWith('.')) throw Error('REGISTRY_METADATA_PATH_INVALID');
  return { name, url: `https://registry.npmjs.org/${encodeURIComponent(name).replace('%40', '@')}` };
}

function authenticated(header, token) {
  const value = typeof header === 'string' ? Buffer.from(header) : Buffer.alloc(0);
  const expected = Buffer.from(`Bearer ${token}`);
  return value.length === expected.length && timingSafeEqual(value, expected);
}

export async function startRegistryBroker({ host = '127.0.0.1', port = 0, token, metadataFixture, fetchMetadata = fetch } = {}) {
  if (typeof token !== 'string' || !/^[a-f0-9]{48}$/.test(token)) throw Error('REGISTRY_BROKER_TOKEN_REQUIRED');
  if (metadataFixture !== undefined && (!metadataFixture || typeof metadataFixture !== 'object' || Array.isArray(metadataFixture) ||
    Buffer.byteLength(JSON.stringify(metadataFixture)) > MAX_TOTAL || Object.keys(metadataFixture).some((name) => !PACKAGE.test(name)))) throw Error('REGISTRY_FIXTURE_INVALID');
  const deadline = Date.now() + 90_000;
  const records = [];
  const cache = new Map();
  let totalBytes = 0;
  let requests = 0;
  let pending = 0;
  const evidence = () => ({ schemaVersion: 'mcpshield.registry-metadata.v1',
    source: metadataFixture === undefined ? 'OFFICIAL_REGISTRY_HTTPS' : 'SYNTHETIC_METADATA_FIXTURE',
    registry: 'https://registry.npmjs.org/', metadataOnly: true, totalBytes, requests, records });
  const reply = (response, status, value) => response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(JSON.stringify(value));
  const server = createServer({ maxHeaderSize: 8192, requestTimeout: 5000 }, async (request, response) => {
    if (!authenticated(request.headers.authorization, token)) return reply(response, 401, { error: 'REGISTRY_AUTH_REQUIRED' });
    if (request.method !== 'GET' || request.headers['content-length'] && request.headers['content-length'] !== '0' || request.headers['transfer-encoding']) return reply(response, 405, { error: 'REGISTRY_GET_ONLY' });
    if (request.url === '/__evidence') return reply(response, 200, evidence());
    if (request.url === '/__health') return reply(response, 200, { ok: true });
    if (++requests > 256 || pending >= 16 || Date.now() >= deadline) return reply(response, 429, { error: 'REGISTRY_BUDGET_EXCEEDED' });
    pending++;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(8000, deadline - Date.now()));
    try {
      const target = registryMetadataTarget(request.url);
      let bytes = cache.get(target.name);
      if (!bytes) {
        if (cache.size >= 128) throw Error('REGISTRY_PACKAGE_LIMIT');
        if (metadataFixture !== undefined) {
          if (!Object.hasOwn(metadataFixture, target.name)) return reply(response, 404, { error: 'REGISTRY_PACKAGE_NOT_FOUND' });
          bytes = Buffer.from(JSON.stringify(metadataFixture[target.name]));
        } else {
          // Credentials/request headers never pass through to the external registry.
          const upstream = await fetchMetadata(target.url, { method: 'GET', redirect: 'error', signal: controller.signal,
            headers: { accept: 'application/vnd.npm.install-v1+json' } });
          if (!upstream.ok || !upstream.body) { await upstream.body?.cancel(); throw Error('REGISTRY_UPSTREAM_FAILED'); }
          const chunks = []; let size = 0;
          for await (const chunk of upstream.body) {
            size += chunk.length;
            if (size > MAX_RESPONSE || totalBytes + size > MAX_TOTAL) { controller.abort(); throw Error('REGISTRY_RESPONSE_LIMIT'); }
            chunks.push(chunk);
          }
          bytes = Buffer.concat(chunks);
        }
        if (bytes.length > MAX_RESPONSE || totalBytes + bytes.length > MAX_TOTAL) throw Error('REGISTRY_RESPONSE_LIMIT');
        const metadata = JSON.parse(bytes);
        if (!metadata || metadata.name !== target.name || !metadata.versions || typeof metadata.versions !== 'object' || Array.isArray(metadata.versions)) throw Error('REGISTRY_METADATA_IDENTITY_INVALID');
        cache.set(target.name, bytes); totalBytes += bytes.length;
        records.push({ packageNameHash: sha(target.name), responseDigest: sha(bytes), bytes: bytes.length, collectedAt: new Date().toISOString() });
      }
      response.writeHead(200, { 'content-type': 'application/vnd.npm.install-v1+json', 'cache-control': 'no-store' }).end(bytes);
    } catch {
      // Registry/package bodies can contain arbitrary text. Only a fixed code escapes.
      reply(response, 502, { error: controller.signal.aborted ? 'REGISTRY_TIMEOUT_OR_SIZE_LIMIT' : 'REGISTRY_METADATA_REJECTED' });
    } finally { pending--; clearTimeout(timer); }
  });
  server.on('connect', (_request, socket) => socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'));
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  return { url: `http://${host}:${server.address().port}`, evidence,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())) };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  if (process.argv[2] === '--evidence') {
    const response = await fetch('http://127.0.0.1:8080/__evidence', { headers: { authorization: `Bearer ${process.env.REGISTRY_BROKER_TOKEN}` }, signal: AbortSignal.timeout(3000) });
    if (!response.ok) throw Error('REGISTRY_EVIDENCE_UNAVAILABLE');
    process.stdout.write(JSON.stringify(await response.json()));
  } else {
    const broker = await startRegistryBroker({ host: '0.0.0.0', port: 8080, token: process.env.REGISTRY_BROKER_TOKEN,
      ...(process.env.MCPSHIELD_REGISTRY_FIXTURE === '1' ? { metadataFixture: JSON.parse(await readFile('/input/registry-fixture.json', 'utf8')) } : {}) });
    process.stdout.write('MCPSHIELD_REGISTRY_BROKER_READY\n');
    const stop = async () => { await broker.close(); process.exit(0); };
    process.on('SIGTERM', stop); process.on('SIGINT', stop);
  }
}
