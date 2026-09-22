import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { test } from 'node:test';

test('export-disabled telemetry preserves real trace context without network requests', async () => {
  let requests = 0;
  const server = createServer((_req, res) => { requests++; res.end('{}'); });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  try {
    const moduleUrl = new URL('../../packages/telemetry/index.mjs', import.meta.url).href;
    const code = `
      import { withSpan, traceHeaders, currentTraceId, shutdownTelemetry } from ${JSON.stringify(moduleUrl)};
      const ids = []; let carrier;
      await withSpan('scan.accept', {}, async () => { ids.push(currentTraceId()); carrier = traceHeaders(); });
      await withSpan('sandbox.execute', {}, async () => { ids.push(currentTraceId()); }, carrier);
      await shutdownTelemetry();
      console.log(JSON.stringify({ids,carrier}));
    `;
    const run = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', code], {
      env: { ...process.env, MCPSHIELD_TELEMETRY_ENABLED: 'false',
        OTEL_EXPORTER_OTLP_ENDPOINT: `http://127.0.0.1:${address.port}` }, timeout: 15000, windowsHide: true,
    });
    const result = JSON.parse(run.stdout.trim());
    assert.match(result.ids[0], /^(?!0{32})[0-9a-f]{32}$/);
    assert.equal(result.ids[0], result.ids[1]);
    assert.match(result.carrier.traceparent, /^00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-00$/);
    assert.equal(requests, 0);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test('official OTLP exporter preserves queue trace parent and excludes bodies, secrets and raw exceptions', async () => {
  const requests: Array<{ url?: string; value: any }> = [];
  const server = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    requests.push({ url: req.url, value: JSON.parse(body) });
    res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  try {
    const moduleUrl = new URL('../../packages/telemetry/index.mjs', import.meta.url).href;
    const code = `
      import { withSpan, traceHeaders, currentTraceId, recordAdmission, shutdownTelemetry } from ${JSON.stringify(moduleUrl)};
      const secret = 'synthetic-not-for-telemetry';
      const ids = [];
      let carrier;
      await withSpan('scan.accept', {'mcpshield.scan_id':'scan-test-1', authorization:secret, body:secret}, async () => {
        ids.push(currentTraceId()); carrier = traceHeaders();
      });
      await withSpan('sandbox.execute', {}, async () => {
        ids.push(currentTraceId());
        await withSpan('evidence.bundle', {}, async () => {throw Error(secret)}).catch(()=>{});
      }, carrier);
      recordAdmission({decision:'BLOCK',riskTier:'FINANCIAL',source:'LIVE',durationSeconds:0.01});
      await shutdownTelemetry();
      console.log(JSON.stringify({ids,carrier}));
    `;
    const run = await promisify(execFile)(process.execPath, ['--input-type=module', '-e', code], {
      env: { ...process.env, MCPSHIELD_TELEMETRY_ENABLED: 'true', OTEL_SERVICE_NAME: 'telemetry-test',
        OTEL_EXPORTER_OTLP_ENDPOINT: `http://127.0.0.1:${address.port}` }, timeout: 15000, windowsHide: true,
    });
    const result = JSON.parse(run.stdout.trim());
    assert.match(result.ids[0], /^[0-9a-f]{32}$/);
    assert.equal(result.ids[0], result.ids[1]);
    assert.match(result.carrier.traceparent, /^00-/);
    const encoded = JSON.stringify(requests);
    assert.doesNotMatch(encoded, /synthetic-not-for-telemetry|authorization|exception.stacktrace/);
    assert.ok(requests.some((request) => request.url === '/v1/metrics'));
    const traces = requests.filter((request) => request.url === '/v1/traces').flatMap((request) =>
      request.value.resourceSpans.flatMap((resource: any) => resource.scopeSpans.flatMap((scope: any) => scope.spans)));
    assert.equal(traces.length, 3);
    assert.equal(new Set(traces.map((span: any) => span.traceId)).size, 1);
    assert.ok(traces.some((span: any) => span.name === 'evidence.bundle' && span.status.code === 2));
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});
