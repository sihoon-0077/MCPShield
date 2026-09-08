import assert from 'node:assert/strict';
import test from 'node:test';
// @ts-expect-error Native ESM release gate, import never invokes Docker.
import { waitForJudgeBackend } from '../../scripts/ops/smoke-release-image.mjs';

const origin = 'http://127.0.0.1:3000';
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
