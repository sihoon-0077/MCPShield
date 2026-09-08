import test from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { startSink } from '../../services/exfil-sink/server.mjs';

function proxyRequest(proxy, path, token, body) {
  const endpoint = new URL(proxy);
  return new Promise((resolve, reject) => {
    const outgoing = request({ hostname: endpoint.hostname, port: endpoint.port, path, method: body ? 'POST' : 'GET',
      headers: { 'proxy-authorization': `Bearer ${token}`, 'content-type': 'application/json' } }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: JSON.parse(Buffer.concat(chunks)) }));
    });
    outgoing.on('error', reject);
    outgoing.end(body ? JSON.stringify(body) : undefined);
  });
}

test('controlled egress proxy routes only synthetic allowed hosts and records redacted canary evidence', async () => {
  const token = 'synthetic-proxy-token-123456789';
  const sink = await startSink({ token, egressAllowHosts: ['mail-api.local'] });
  try {
    assert.equal((await proxyRequest(sink.url, 'http://mail-api.local/messages', 'wrong')).status, 407);
    const canary = 'CANARY::synthetic-scan::CUSTOMER_RECORD::001122';
    const allowed = await proxyRequest(sink.url, 'http://mail-api.local/messages', token, { context: canary });
    assert.equal(allowed.status, 200);
    assert.equal(allowed.body.synthetic, true);
    for (const destination of ['http://169.254.169.254/metadata', 'http://127.0.0.1/private', 'http://mail-api.local:8080/private', 'http://unlisted.test/collect', 'https://mail-api.local/tls']) {
      assert.equal((await proxyRequest(sink.url, destination, token)).status, 403);
    }
    assert.ok(sink.events.some(({ type }) => type === 'CANARY_EGRESS'));
    assert.equal(sink.events.filter(({ type }) => type === 'EGRESS_BLOCKED').length, 5);
    assert.equal(JSON.stringify(sink.events).includes(canary), false);
    assert.equal(JSON.stringify(sink.events).includes(token), false);
    await assert.rejects(() => startSink({ token, egressAllowHosts: ['real-service.example.com'] }), /synthetic/);
  } finally { await sink.close(); }
});
