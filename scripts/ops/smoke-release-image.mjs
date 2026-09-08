import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

// Run only the image built by this job, with synthetic data and temporary credentials.
const image = process.argv[2];
assert.match(image ?? '', /^sha256:[a-f0-9]{64}$/);
const docker = (...args) => execFileSync('docker', args, { encoding: 'utf8', timeout: 30_000, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
const env = ['ADMIN_API_TOKEN', 'SCANNER_API_TOKEN'].flatMap(key => ['-e', `${key}=${randomBytes(32).toString('hex')}`]);
let container, client;
try {
  container = docker('run', '--detach', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '1g', '--pids-limit', '128',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m', '-p', '127.0.0.1::3000', '-e', 'HOSTNAME=0.0.0.0', '-e', 'PORT=3000', ...env, image);
  assert.match(container, /^[a-f0-9]{64}$/);
  const state = JSON.parse(docker('inspect', container))[0];
  assert.equal(state.Config.User, 'node', 'Release must not run as root');
  const port = state.NetworkSettings.Ports['3000/tcp'][0].HostPort;
  const origin = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let attempt = 0; attempt < 40; attempt++) {
    try { const r = await fetch(`${origin}/try`, { signal: AbortSignal.timeout(2000) }); if (r.status === 200) { await r.arrayBuffer(); ready = true; break; } } catch { /* bounded startup polling */ }
    await setTimeout(500);
  }
  assert.ok(ready, 'Release image did not start its public web experience');
  const landing = await fetch(`${origin}/mcp`, { headers: { accept: 'text/html' }, signal: AbortSignal.timeout(5000) });
  assert.equal(landing.status, 200); assert.match(landing.headers.get('content-type') ?? '', /^text\/html/);
  assert.match(await landing.text(), /MCPShield/);
  for (const era of ['legacy', 'modern']) {
    client = new Client({ name: 'release-image-smoke', version: '1' }, { versionNegotiation: { mode: era === 'modern' ? { pin: '2026-07-28' } : 'legacy' } });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${origin}/mcp`)), { timeout: 10_000 });
    const tools = await client.listTools({}, { timeout: 10_000 });
    assert.deepEqual(tools.tools.map(t => t.name), ['list_messages']);
    assert.equal(tools.tools[0].annotations?.readOnlyHint, true);
    const result = await client.callTool({ name: 'list_messages', arguments: {} }, undefined, { timeout: 10_000 });
    assert.notEqual(result.isError, true);
    assert.deepEqual(JSON.parse(result.content[0].text), { ok: true, messages: [{ id: 'demo-1', subject: 'Welcome' }] });
    await client.close(); client = undefined;
  }
  docker('stop', '--time', '10', container);
  const stopped = JSON.parse(docker('inspect', container))[0].State;
  assert.equal(stopped.Running, false); assert.equal(stopped.OOMKilled, false);
  assert.ok([0, 143].includes(stopped.ExitCode), `Release did not terminate gracefully: ${stopped.ExitCode}`);
  console.log(JSON.stringify({ image, web: 'PASS', mcpLegacy: 'PASS', mcpModern: 'PASS', data: 'SYNTHETIC_REPLAY', lifecycle: 'PASS' }));
} finally {
  await client?.close().catch(() => {});
  if (container && /^[a-f0-9]{64}$/.test(container)) docker('rm', '--force', container);
}
