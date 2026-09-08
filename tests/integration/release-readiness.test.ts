import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { buildApp } from '../../apps/api/src/app.js';
// @ts-expect-error Native ESM release gate, import never invokes Docker.
import { waitForJudgeBackend, waitForMcpLanding, smokeJudgeExperience } from '../../scripts/ops/smoke-release-image.mjs';

const origin = 'http://127.0.0.1:3000';
test('release smoke contract exercises the real API and complete synthetic judge session', async () => {
  const app = await buildApp({ databasePath: ':memory:', judgeDemo: true,
    adminApiToken: 'synthetic-release-admin-token', scannerApiToken: 'synthetic-release-scanner-token' });
  try {
    await app.listen({ host: '127.0.0.1', port: 0 });
    const address = app.server.address();
    assert.ok(address && typeof address !== 'string');
    const local = `http://127.0.0.1:${address.port}`;
    // Same path translation as the web proxy, with actual HTTP and API handlers.
    const proxyFetch = (url: string, init: RequestInit) => fetch(url.replace('/api/judge/', '/api/demo/'), init);
    await waitForJudgeBackend(local, proxyFetch);
    assert.deepEqual(await smokeJudgeExperience(local, proxyFetch), {
      backend: 'PASS', safe: 'ALLOW', malicious: 'BLOCK_BEFORE_SPAWN', source: 'LIVE_DEMO', synthetic: true, ledger: 'LOCAL_DEMO' });
  } finally { await app.close(); }
});
test('independent CI diagnostics never remove upstream success gates from image signing or retention', () => {
  const workflow = readFileSync(new URL('../../.github/workflows/frontend-gateway-devops.yml', import.meta.url), 'utf8');
  const jobs = workflow.split(/^  (?=[a-z-]+:\s*$)/m);
  for (const name of ['repeat-demo', 'signed-image']) {
    const job = jobs.find((part) => part.startsWith(`${name}:`));
    assert.ok(job, name);
    assert.match(job, /if: \$\{\{ !cancelled\(\) && github.event_name == 'workflow_dispatch'/);
    assert.match(job, /needs: \[verify, postgres\]/);
  }
  const steps = workflow.split(/^      - name: /m);
  for (const name of ['Sign build provenance for the actual image archive', 'Sign image SBOM attestation',
    'Verify build signature against this repository identity', 'Retain bounded downloadable image and evidence']) {
    const matches = steps.filter((step) => step.startsWith(`${name}\n`) || step.startsWith(`${name}\r\n`));
    assert.equal(matches.length, 1, name);
    // No status function here: GitHub's implicit success() must also require earlier image checks to pass.
    assert.match(matches[0], /^        if: needs\.verify\.result == 'success' && needs\.postgres\.result == 'success'\r?$/m);
  }
});
const missing = () => Response.json({ schemaVersion: '1.0.0', error: { code: 'DEMO_SESSION_NOT_FOUND' } }, { status: 404 });
test('release readiness waits for the real demo route without creating or mutating a session', async () => {
  const paths = new Set<string>(); let calls = 0;
  await waitForJudgeBackend(origin, async (url: string, init: RequestInit) => {
    assert.equal(init.method, 'GET'); assert.equal(init.body, undefined); assert.equal(init.redirect, 'error');
    assert.equal(init.headers && new Headers(init.headers).get('authorization'), null);
    const path = new URL(url).pathname; paths.add(path);
    assert.match(path, /^\/api\/judge\/sessions\/[a-f0-9-]{36}$/);
    return ++calls === 1 ? Response.json({ error: 'unavailable' }, { status: 503 }) : missing();
  });
  assert.equal(calls, 2); assert.equal(paths.size, 1);
});
test('readiness rejects a disabled/mismatched demo route, unexpected responses and external origins', async () => {
  await assert.rejects(waitForJudgeBackend('https://external.example', () => assert.fail()), /loopback/);
  for (const response of [Response.json({}, { status: 404 }), Response.json({}, { status: 200 }), Response.json({}, { status: 403 })]) {
    await assert.rejects(waitForJudgeBackend(origin, async () => response), /READINESS_ROUTE_MISMATCH|RELEASE_JUDGE_HTTP/);
  }
});
test('readiness has one total deadline and cancels stalled bodies', async () => {
  let cancelled = false;
  await assert.rejects(waitForJudgeBackend(origin, async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }), { status: 503 }), 30), /RELEASE_BACKEND_NOT_READY/);
  assert.equal(cancelled, true);
});

test('MCP landing readiness tolerates independent cold start using only bounded read-only requests', async () => {
  let calls = 0;
  await waitForMcpLanding(origin, async (url: string, init: RequestInit) => {
    assert.equal(url, `${origin}/mcp`); assert.equal(init.method, 'GET'); assert.equal(init.body, undefined);
    assert.equal(init.redirect, 'error'); assert.equal(init.cache, 'no-store');
    assert.equal(new Headers(init.headers).get('authorization'), null);
    if (++calls === 1) throw new TypeError('synthetic connection refused');
    if (calls < 4) return new Response(null, { status: calls === 2 ? 500 : 503 });
    return new Response('<html>MCPShield</html>', { headers: { 'content-type': 'text/html; charset=utf-8' } });
  });
  assert.equal(calls, 4);
});

test('MCP landing readiness rejects wrong routes, oversized bodies and external origins', async () => {
  await assert.rejects(waitForMcpLanding('https://external.example', () => assert.fail()), /loopback/);
  for (const response of [new Response(null, { status: 404 }), Response.json({ name: 'MCPShield' }),
    new Response('wrong page', { headers: { 'content-type': 'text/html' } }),
    new Response('MCPShield'.padEnd(1_048_577, 'x'), { headers: { 'content-type': 'text/html' } })]) {
    let calls = 0;
    await assert.rejects(waitForMcpLanding(origin, async () => { calls++; return response; }), /RELEASE_MCP_/);
    assert.equal(calls, 1);
  }
});

test('MCP landing readiness cancels stalled fetch/body within its total deadline', async () => {
  let signal: AbortSignal | undefined;
  await assert.rejects(waitForMcpLanding(origin, (_: string, init: RequestInit) => {
    signal = init.signal!; return new Promise(() => {});
  }, 30), /RELEASE_MCP_NOT_READY/);
  assert.equal(signal?.aborted, true);
  let cancelled = false;
  await assert.rejects(waitForMcpLanding(origin, async () => new Response(new ReadableStream({ cancel() { cancelled = true; } }),
    { headers: { 'content-type': 'text/html' } }), 30), /RELEASE_MCP_NOT_READY/);
  assert.equal(cancelled, true);
});
