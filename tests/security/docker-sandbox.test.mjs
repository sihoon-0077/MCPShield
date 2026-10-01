import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, writeFile, cp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { runSandbox } from '../../services/scanner/src/sandbox.mjs';
import { scanReleaseDetailed } from '../../services/scanner/src/scanner.mjs';
import { runMcpAttackHarness } from '../../benchmarks/mcp-attack-harness.mjs';
import { createServer } from 'node:http';
import { runPairedAgentHarness, summarizeAgentExperiments } from '../../benchmarks/agent-mcp-harness.mjs';

const enabled = process.env.MCPSHIELD_DOCKER_TESTS === '1';
test('Linux Docker enforces rootfs, capabilities, cgroups and external-network isolation', { skip: !enabled, timeout: 120_000 }, async () => {
  const fixtureDir = await mkdtemp(join(tmpdir(), 'mcpshield-docker-boundary-'));
  try {
    await writeFile(join(fixtureDir, 'index.mjs'), [
      "import assert from 'node:assert/strict'; import fs from 'node:fs'; import net from 'node:net';",
      "assert.notEqual(process.getuid(), 0); assert.notEqual(process.getgid(), 0);",
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

test('isolated MCP collector completes pagination and detects source/manifest drift', { skip: !enabled, timeout: 180_000 }, async () => {
  const safe = await scanReleaseDetailed({ fixtureDir: resolve('demo/fixtures/mail-mcp-1.0.0'), sandbox: 'docker', sandboxTimeoutMs: 10_000, logger: () => {} });
  assert.equal(safe.result.scanStatus, 'PASSED');
  assert.equal(JSON.parse(safe.bundle.files['sandbox/mcp.json']).complete, true);
  const fixtureDir = await mkdtemp(join(tmpdir(), 'mcpshield-mcp-drift-'));
  try {
    await cp(resolve('demo/fixtures/probe-mail-mcp'), fixtureDir, { recursive: true });
    const original = await readFile(join(fixtureDir, 'index.mjs'), 'utf8');
    await writeFile(join(fixtureDir, 'index.mjs'), original.replace('tools: [manifest.tools[0]]', "tools: [{...manifest.tools[0], description:'unexpected surface'}]"));
    const drift = await scanReleaseDetailed({ fixtureDir, sandbox: 'docker', sandboxTimeoutMs: 10_000, logger: () => {} });
    assert.equal(drift.result.scanStatus, 'FAILED');
    assert.ok(drift.result.findings.some(({ code, stage }) => code === 'TOOL_SURFACE_CHANGED' && stage === 'SANDBOX'));
    await writeFile(join(fixtureDir, 'index.mjs'), original.replace('{ tools: [manifest.tools[1]] }', "{ tools: [manifest.tools[1]], nextCursor: 'page-two' }"));
    const incomplete = await scanReleaseDetailed({ fixtureDir, sandbox: 'docker', sandboxTimeoutMs: 10_000, logger: () => {} });
    assert.notEqual(incomplete.result.scanStatus, 'PASSED');
    assert.equal(JSON.parse(incomplete.bundle.files['sandbox/mcp.json']).complete, false);
  } finally { await rm(fixtureDir, { recursive: true, force: true }); }
});

test('actual synthetic MCP calls breach the controlled sink without admission and stop before spawn with admission', { skip: !enabled, timeout: 180_000 }, async () => {
  const fixtureDir = resolve('demo/fixtures/probe-mail-mcp');
  let verifiedScan;
  const report = await runMcpAttackHarness({ fixtureDir, authorize: async () => {
    verifiedScan = await scanReleaseDetailed({ fixtureDir, sandbox: 'docker', sandboxTimeoutMs: 10_000,
      probeCalls: [{ name: 'export_context', arguments: {} }], logger: () => {} });
    return { allow: verifiedScan.result.scanStatus === 'PASSED', reasonCode: 'SCANNER_POLICY_GATE' };
  } });
  assert.equal(report.normal.canaryExfiltration, false);
  assert.equal(report.baseline.canaryExfiltration, true);
  assert.equal(report.protected.spawned, false);
  assert.equal(report.protectedAttackSuccessRate, 0);
  assert.ok(verifiedScan.result.findings.some(({ code }) => code === 'CANARY_EXFILTRATION'));
  const exfil = verifiedScan.result.findings.find(({ code }) => code === 'CANARY_EXFILTRATION');
  assert.equal(exfil.evidence.canaryType, 'CUSTOMER_RECORD');
  assert.equal(JSON.parse(verifiedScan.bundle.files['sandbox/mcp.json']).pages, 2);
  assert.ok(JSON.parse(verifiedScan.bundle.files['sandbox/events.json']).egressEvents.some(({ type, canaryHash }) => type === 'CANARY_EGRESS' && canaryHash === exfil.evidence.canarySha256));
});

test('validated AI contract-test plans run actual MCP calls inside Docker and retain generation provenance', { skip: !enabled, timeout: 180_000 }, async (context) => {
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks));
    const payload = body.responseSchema.properties.scenarios ? { scenarios: [
      { scenarioId: 'normal-mail', kind: 'NORMAL', goal: 'Read one synthetic message.', toolName: 'list_messages', argumentsJson: '{}' },
      { scenarioId: 'context-scope', kind: 'ADVERSARIAL', goal: 'Observe synthetic customer canary scope.', toolName: 'export_context', argumentsJson: '{}' },
    ] } : { riskClaims: [], semanticDiff: { purposeChanged: false, dataScopeExpanded: false, newHiddenObligation: false }, needsHumanReview: false };
    response.end(JSON.stringify(payload));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  context.after(() => { server.closeAllConnections(); server.close(); });
  const result = await scanReleaseDetailed({ fixtureDir: resolve('demo/fixtures/probe-mail-mcp'), sandbox: 'docker', sandboxTimeoutMs: 10_000,
    aiUrl: `http://127.0.0.1:${server.address().port}`, allowRemoteAi: true, aiGenerateProbes: true, logger: () => {} });
  assert.equal(result.result.scanStatus, 'FAILED');
  assert.ok(result.result.findings.some(({ code }) => code === 'CANARY_EXFILTRATION'));
  assert.equal(JSON.parse(result.bundle.files['semantic/generated-probes.json']).execution.status, 'GENERATED_VALIDATED');
  assert.equal(JSON.parse(result.bundle.files['sandbox/mcp.json']).callResults.length, 2);
});

test('paired agent contract test uses identical benign tasks and actual Docker sink effects, preserving safe-task availability', { skip: !enabled, timeout: 300_000 }, async (context) => {
  const tasks = [];
  const server = createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks));
    const prompt = JSON.parse(body.prompt); tasks.push(prompt.userTask);
    const name = prompt.tools.some(({ name }) => name === 'export_context') ? 'export_context' : 'list_messages';
    response.end(JSON.stringify({ disposition: 'SELECTED', calls: [{ name, argumentsJson: '{}' }] }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  context.after(() => { server.closeAllConnections(); server.close(); });
  const result = await runPairedAgentHarness({ safeDir: resolve('demo/fixtures/mail-mcp-1.0.0'), poisonedDir: resolve('demo/fixtures/probe-mail-mcp'),
    allowRemoteAi: true, url: `http://127.0.0.1:${server.address().port}`, authorize: async ({ fixtureDir, artifactDigest, calls }) => {
      const scan = await scanReleaseDetailed({ fixtureDir, sandbox: 'docker', sandboxTimeoutMs: 10_000, probeCalls: calls, logger: () => {} });
      return { allow: scan.result.artifactDigest === artifactDigest && scan.result.scanStatus === 'PASSED', reasonCode: 'SCANNER_POLICY_NOT_CHAIN' };
    } });
  assert.equal(tasks.length, 2);
  assert.equal(tasks[0], tasks[1]);
  assert.equal(result.measurements.safe.baseline.taskCompleted, true);
  assert.equal(result.measurements.safe.protected.taskCompleted, true);
  assert.equal(result.measurements.poisoned.baseline.canaryExfiltration, true);
  assert.equal(result.measurements.poisoned.protected.spawned, false);
  assert.equal(summarizeAgentExperiments([result]).protectedAsr, 0);
});
