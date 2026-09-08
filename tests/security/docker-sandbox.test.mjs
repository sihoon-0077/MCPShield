import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { runSandbox } from '../../services/scanner/src/sandbox.mjs';

const enabled = process.env.MCPSHIELD_DOCKER_TESTS === '1';
test('Linux Docker enforces rootfs, capabilities, cgroups and external-network isolation', { skip: !enabled, timeout: 120_000 }, async () => {
  const fixtureDir = await mkdtemp(join(tmpdir(), 'mcpshield-docker-boundary-'));
  try {
    await writeFile(join(fixtureDir, 'index.mjs'), [
      "import assert from 'node:assert/strict'; import fs from 'node:fs'; import net from 'node:net';",
      "assert.throws(() => fs.writeFileSync('/rootfs-must-stay-readonly', 'synthetic'));",
      "assert.throws(() => fs.writeFileSync('/fixture/write-must-fail', 'synthetic'));",
      "assert.equal(fs.existsSync('/var/run/docker.sock'), false);",
      "assert.match(fs.readFileSync('/proc/self/status', 'utf8'), /NoNewPrivs:\\s+1/);",
      "assert.match(fs.readFileSync('/proc/self/status', 'utf8'), /CapEff:\\s+0000000000000000/);",
      "assert.equal(fs.readFileSync('/sys/fs/cgroup/pids.max', 'utf8').trim(), '64');",
      "assert.equal(Number(fs.readFileSync('/sys/fs/cgroup/memory.max', 'utf8').trim()), 134217728);",
      "fs.writeFileSync('/tmp/synthetic', 'allowed bounded tmpfs');",
      "await new Promise((resolve, reject) => { const socket = net.connect({host:'198.51.100.1',port:80}); socket.setTimeout(400); socket.on('connect', () => { socket.destroy(); reject(new Error('external egress unexpectedly allowed')); }); socket.on('timeout', () => { socket.destroy(); resolve(); }); socket.on('error', resolve); });",
    ].join('\n'));
    const result = await runSandbox({ mode: 'docker', fixtureDir, entrypoint: 'index.mjs', timeoutMs: 10_000 });
    assert.equal(result.mode, 'DOCKER');
    assert.equal(result.error, null);
    assert.equal(result.exitCode, 0);
    assert.equal(result.timedOut, false);
  } finally { await rm(fixtureDir, { recursive: true, force: true }); }
});

test('Linux Docker canary detection and timeout cleanup execute against real containers', { skip: !enabled, timeout: 120_000 }, async () => {
  const malicious = await runSandbox({ mode: 'docker', fixtureDir: resolve('demo/fixtures/mail-mcp-1.0.1'), entrypoint: 'index.mjs', timeoutMs: 10_000 });
  assert.equal(malicious.canaryObserved, true);
  const fixtureDir = await mkdtemp(join(tmpdir(), 'mcpshield-docker-timeout-'));
  try {
    await writeFile(join(fixtureDir, 'index.mjs'), 'setTimeout(() => {}, 30_000);');
    const timed = await runSandbox({ mode: 'docker', fixtureDir, entrypoint: 'index.mjs', timeoutMs: 1_000 });
    assert.equal(timed.timedOut, true);
  } finally { await rm(fixtureDir, { recursive: true, force: true }); }
});
