import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { setTimeout } from 'node:timers/promises';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

// One total deadline and size budget cover successful and error responses; never log response bodies.
async function judgeRequest(origin, path, method, status, body, fetchImpl, timeoutMs = 20_000) {
  const controller = new AbortController();
  let timer, reader;
  const deadline = new Promise((_, reject) => { timer = globalThis.setTimeout(() => { controller.abort(); reject(new Error('RELEASE_JUDGE_TIMEOUT')); }, timeoutMs); });
  try {
    const response = await Promise.race([fetchImpl(`${origin}/api/judge/${path}`, {
      method, headers: { origin, accept: 'application/json', ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body), signal: controller.signal, redirect: 'error', cache: 'no-store',
    }), deadline]);
    const chunks = []; let bytes = 0;
    reader = response.body?.getReader();
    if (reader) while (true) {
      const { done, value } = await Promise.race([reader.read(), deadline]);
      if (done) break;
      bytes += value.byteLength;
      assert.ok(bytes <= 65_536, 'RELEASE_JUDGE_RESPONSE_TOO_LARGE');
      chunks.push(Buffer.from(value));
    }
    assert.ok(response.status === status, `RELEASE_JUDGE_HTTP_${response.status}`);
    if (status === 204) { assert.ok(bytes === 0, 'RELEASE_JUDGE_UNEXPECTED_DELETE_BODY'); return; }
    assert.ok(/^application\/json\b/i.test(response.headers.get('content-type') ?? ''), 'RELEASE_JUDGE_JSON_REQUIRED');
    try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new Error('RELEASE_JUDGE_INVALID_JSON'); }
  } finally { globalThis.clearTimeout(timer); controller.abort(); void reader?.cancel().catch(() => {}); }
}

export async function waitForJudgeBackend(value, fetchImpl = fetch, timeoutMs = 20_000) {
  const url = new URL(value);
  assert.ok(url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) && !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash, 'Release readiness accepts only a loopback image origin');
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 20_000, 'RELEASE_READINESS_BUDGET_INVALID');
  const deadline = performance.now() + timeoutMs, path = `sessions/${randomUUID()}`;
  // A web 200 proves neither API startup nor the enabled demo route. A GET for a
  // fresh random ID verifies both without creating/retrying a stateful session.
  while (performance.now() < deadline) {
    try {
      const result = await judgeRequest(url.origin, path, 'GET', 404, undefined, fetchImpl, Math.max(1, Math.min(2000, deadline - performance.now())));
      assert.ok(result?.schemaVersion === '1.0.0' && result.error?.code === 'DEMO_SESSION_NOT_FOUND', 'RELEASE_READINESS_ROUTE_MISMATCH');
      return;
    } catch (error) {
      if (!(error instanceof TypeError) && !['RELEASE_JUDGE_HTTP_503', 'RELEASE_JUDGE_TIMEOUT'].includes(error.message)) throw error;
    }
    await setTimeout(Math.max(0, Math.min(500, deadline - performance.now())));
  }
  throw new Error('RELEASE_BACKEND_NOT_READY');
}

export async function smokeJudgeExperience(value, fetchImpl = fetch) {
  const url = new URL(value);
  assert.ok(url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) && !url.username && !url.password && url.pathname === '/' && !url.search && !url.hash, 'Release smoke accepts only a loopback image origin');
  const origin = url.origin;
  const actions = ['SCAN_SAFE', 'VOTE_SAFE_A', 'VOTE_SAFE_B', 'RUN_SAFE', 'SELECT_MALICIOUS', 'SCAN_MALICIOUS', 'VOTE_FAIL_A', 'VOTE_FAIL_B', 'RUN_MALICIOUS'];
  const ids = ['mail-mcp@1.0.0', 'mail-mcp@1.0.1'];
  const safeResult = { ok: true, messages: [{ id: 'demo-1', subject: 'Welcome' }] };
  let sessionId, failed = false;
  function check(state, step) {
    assert.ok(state?.sessionId === sessionId && state.schemaVersion === '1.0.0' && state.synthetic === true && state.source === 'LIVE_DEMO' && state.ledgerMode === 'LOCAL_DEMO', 'Release judge session identity/source mismatch');
    assert.ok(state.step === step && state.nextAction === (actions[step] ?? null) && state.complete === (step === actions.length), 'Release judge did not advance the expected action');
    assert.ok(Array.isArray(state.releases) && state.releases.length === 2 && state.releases.every((r, i) => r.releaseId === ids[i]), 'Release judge changed its fixed fixture scope');
    assert.ok(state.releases[0].scanStatus === (step >= 1 ? 'PASSED' : 'NOT_RUN') && state.releases[0].status === (step >= 3 ? 'VERIFIED' : 'UNVERIFIED'), 'Safe scan/quorum state mismatch');
    assert.ok(state.releases[1].scanStatus === (step >= 6 ? 'FAILED' : 'NOT_RUN') && state.releases[1].status === (step >= 8 ? 'REVOKED' : 'UNVERIFIED'), 'Malicious scan/quorum state mismatch');
    assert.ok(state.selectedRelease === ids[step >= 5 ? 1 : 0], 'Release judge update selection mismatch');
    const decisions = step >= 8 ? ['PASS', 'PASS', 'FAIL', 'FAIL'] : step >= 7 ? ['PASS', 'PASS', 'FAIL'] : step >= 3 ? ['PASS', 'PASS'] : step >= 2 ? ['PASS'] : [];
    assert.ok(Array.isArray(state.votes) && state.votes.length === decisions.length && state.votes.every((vote, i) => vote.decision === decisions[i] && vote.releaseId === ids[i < 2 ? 0 : 1] && /^0x[a-f0-9]{64}$/.test(vote.signatureHash)), 'Release judge signed votes mismatch');
    for (const releaseId of ids) {
      const votes = state.votes.filter(vote => vote.releaseId === releaseId);
      assert.ok(votes.every(vote => /^0x[0-9a-fA-F]{40}$/.test(vote.address)) && new Set(votes.map(vote => vote.address.toLowerCase())).size === votes.length, 'Release judge validators are not distinct');
    }
    assert.ok(Array.isArray(state.executions) && state.executions.length === (step >= 9 ? 2 : step >= 4 ? 1 : 0), 'Release judge execution count mismatch');
    if (step >= 4) {
      const execution = state.executions[0];
      assert.ok(execution.releaseId === ids[0] && execution.decision === 'ALLOW' && execution.spawnAttempted === true && JSON.stringify(execution.result) === JSON.stringify(safeResult), 'Release judge did not execute the safe MCP tool');
    }
    if (step >= 6) assert.ok(Array.isArray(state.findings) && state.findings.some(f => f.code === 'CANARY_EXFILTRATION'), 'Release judge did not detect the synthetic canary');
    if (step >= 9) {
      const execution = state.executions[1];
      assert.ok(execution.releaseId === ids[1] && execution.decision === 'BLOCK' && execution.spawnAttempted === false && execution.reasonCode === 'RELEASE_REVOKED' && execution.result === undefined, 'Release judge did not block before spawn');
    }
  }
  try {
    let state = await judgeRequest(origin, 'sessions', 'POST', 201, undefined, fetchImpl);
    assert.ok(typeof state?.sessionId === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(state.sessionId), 'Release judge did not create a private synthetic session');
    sessionId = state.sessionId; check(state, 0);
    for (const [index, action] of actions.entries()) {
      state = await judgeRequest(origin, `sessions/${sessionId}/actions`, 'POST', 200, { action }, fetchImpl);
      check(state, index + 1);
    }
  } catch (error) { failed = true; throw error; }
  finally {
    // Never enumerate/reset other sessions. The outer runner also removes this disposable container on failure.
    if (sessionId) try { await judgeRequest(origin, `sessions/${sessionId}`, 'DELETE', 204, undefined, fetchImpl); }
    catch { if (!failed) throw new Error('RELEASE_JUDGE_SESSION_CLEANUP_FAILED'); }
  }
  return { backend: 'PASS', safe: 'ALLOW', malicious: 'BLOCK_BEFORE_SPAWN', source: 'LIVE_DEMO', synthetic: true, ledger: 'LOCAL_DEMO' };
}

// Run only the image built by this job, with synthetic data and temporary credentials.
async function main(image) {
assert.match(image ?? '', /^sha256:[a-f0-9]{64}$/);
const docker = (...args) => execFileSync('docker', args, { encoding: 'utf8', timeout: 30_000, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const env = ['ADMIN_API_TOKEN', 'SCANNER_API_TOKEN'].flatMap(key => ['-e', `${key}=${randomBytes(32).toString('hex')}`]);
let container, client, stage = 'CONTAINER_START';
try {
  // Match the user's Free-plan envelope conservatively: 0.5 GB, one CPU, no swap.
  // This is a bounded demo smoke, not a sustained-load or billing guarantee.
  container = docker('run', '--detach', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '500000000', '--memory-swap', '500000000', '--cpus', '1', '--pids-limit', '128',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m', '-p', '127.0.0.1::3000', '-e', 'HOSTNAME=0.0.0.0', '-e', 'PORT=3000', ...env, image);
  assert.match(container, /^[a-f0-9]{64}$/);
  const state = JSON.parse(docker('inspect', container))[0];
  stage = 'CONTAINER_POLICY';
  assert.equal(state.Config.User, 'node', 'Release must not run as root');
  assert.equal(state.HostConfig.Memory, 500000000); assert.equal(state.HostConfig.MemorySwap, 500000000);
  assert.equal(state.HostConfig.NanoCpus, 1000000000);
  const port = state.NetworkSettings.Ports['3000/tcp'][0].HostPort;
  const origin = `http://127.0.0.1:${port}`;
  let ready = false;
  stage = 'WEB_READINESS';
  for (let attempt = 0; attempt < 40; attempt++) {
    try { const r = await fetch(`${origin}/try`, { signal: AbortSignal.timeout(2000) }); if (r.status === 200) { await r.arrayBuffer(); ready = true; break; } } catch { /* bounded startup polling */ }
    await setTimeout(500);
  }
  assert.ok(ready, 'Release image did not start its public web experience');
  stage = 'MCP_LANDING';
  const landing = await fetch(`${origin}/mcp`, { headers: { accept: 'text/html' }, signal: AbortSignal.timeout(5000) });
  assert.equal(landing.status, 200); assert.match(landing.headers.get('content-type') ?? '', /^text\/html/);
  assert.match(await landing.text(), /MCPShield/);
  stage = 'JUDGE_READINESS';
  await waitForJudgeBackend(origin);
  stage = 'JUDGE_FLOW';
  const judge = await smokeJudgeExperience(origin);
  for (const era of ['legacy', 'modern']) {
    stage = era === 'legacy' ? 'MCP_LEGACY_CONNECT' : 'MCP_MODERN_CONNECT';
    client = new Client({ name: 'release-image-smoke', version: '1' }, { versionNegotiation: { mode: era === 'modern' ? { pin: '2026-07-28' } : 'legacy' } });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${origin}/mcp`)), { timeout: 10_000 });
    stage = era === 'legacy' ? 'MCP_LEGACY_TOOLS' : 'MCP_MODERN_TOOLS';
    const tools = await client.listTools({}, { timeout: 10_000 });
    assert.deepEqual(tools.tools.map(t => t.name), ['list_messages']);
    assert.equal(tools.tools[0].annotations?.readOnlyHint, true);
    stage = era === 'legacy' ? 'MCP_LEGACY_CALL' : 'MCP_MODERN_CALL';
    const result = await client.callTool({ name: 'list_messages', arguments: {} }, undefined, { timeout: 10_000 });
    assert.notEqual(result.isError, true);
    assert.deepEqual(JSON.parse(result.content[0].text), { ok: true, messages: [{ id: 'demo-1', subject: 'Welcome' }] });
    await client.close(); client = undefined;
  }
  stage = 'SHUTDOWN';
  docker('stop', '--time', '10', container);
  const stopped = JSON.parse(docker('inspect', container))[0].State;
  assert.equal(stopped.Running, false); assert.equal(stopped.OOMKilled, false);
  assert.ok([0, 143].includes(stopped.ExitCode), `Release did not terminate gracefully: ${stopped.ExitCode}`);
  console.log(JSON.stringify({ image, web: 'PASS', mcpLegacy: 'PASS', mcpModern: 'PASS', mcpData: 'SYNTHETIC_REPLAY', judge, lifecycle: 'PASS', resourceEnvelope: { memoryBytes: 500000000, cpus: 1, swapBytes: 0, sustainedLoadMeasured: false } }));
} catch (error) {
  if (container && /^[a-f0-9]{64}$/.test(container)) {
    try {
      const state = JSON.parse(docker('inspect', container))[0].State;
      const output = spawnSync('docker', ['logs', '--tail=80', container], { encoding: 'utf8', timeout: 5000, maxBuffer: 65_536, stdio: ['ignore', 'pipe', 'pipe'] });
      const logs = `${output.stdout ?? ''}\n${output.stderr ?? ''}`;
      console.error(JSON.stringify({ event: 'RELEASE_SMOKE_FAILED', stage, running: state.Running, oomKilled: state.OOMKilled, exitCode: state.ExitCode,
        logsRead: !output.error && output.status === 0,
        diagnosticCodes: ['ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND', 'ECONNREFUSED', 'EADDRINUSE', 'ERR_SQLITE_ERROR'].filter(code => logs.includes(code)) }));
    } catch { console.error('{"event":"RELEASE_SMOKE_DIAGNOSTICS_UNAVAILABLE"}'); }
  }
  // execFileSync errors may contain argv, including this run's synthetic API
  // credentials. Never let Node print the raw subprocess exception object.
  throw new Error(/^RELEASE_[A-Z_0-9]+$/.test(error?.message ?? '') ? error.message : 'RELEASE_IMAGE_SMOKE_FAILED');
} finally {
  await client?.close().catch(() => {});
  if (container && /^[a-f0-9]{64}$/.test(container)) {
    try { docker('rm', '--force', container); } catch { throw new Error('RELEASE_CONTAINER_CLEANUP_FAILED'); }
  }
}
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) await main(process.argv[2]);
