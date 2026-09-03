import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  analyzeSemantics,
  analyzeSemanticsFallback,
  artifactDigest,
  buildAiPrompt,
  scanRelease,
  toolSurfaceHash,
} from '../../services/scanner/src/scanner.mjs';
import { assertFinding, assertScanResult } from '../../services/scanner/src/schema.mjs';
import { assertCanonicalScanResult } from '../../services/scanner/src/protocol-schema.mjs';
import { submitScanResult } from '../../services/scanner/src/submit.mjs';
import { DEMO_CANARY } from '../../services/scanner/src/sandbox.mjs';
import { startSink } from '../../services/exfil-sink/server.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const SAFE = join(ROOT, 'demo/fixtures/mail-mcp-1.0.0');
const MALICIOUS = join(ROOT, 'demo/fixtures/mail-mcp-1.0.1');
const quiet = () => {};

test('safe 1.0.0 produces a schema-valid PASSED result without critical findings', async () => {
  const result = await scanRelease({ fixtureDir: SAFE, logger: quiet });
  assertScanResult(result);
  assert.equal(result.releaseId, 'mail-mcp@1.0.0');
  assert.equal(result.scanStatus, 'PASSED');
  assert.equal(result.findings.some(({ severity }) => severity === 'CRITICAL'), false);
});

test('malicious 1.0.1 deterministically leaks only the dummy canary to the controlled sink', async () => {
  const result = await scanRelease({ fixtureDir: MALICIOUS, baselineDir: SAFE, logger: quiet });
  assertScanResult(result);
  assert.equal(result.releaseId, 'mail-mcp@1.0.1');
  assert.equal(result.scanStatus, 'FAILED');
  const codes = new Set(result.findings.map(({ code }) => code));
  for (const code of ['SENSITIVE_FILE_READ', 'UNDECLARED_EGRESS', 'CANARY_EXFILTRATION', 'TOOL_SURFACE_CHANGED']) {
    assert.equal(codes.has(code), true, `missing ${code}`);
  }
  assert.equal(result.findings.some(({ code, stage }) => code === 'SENSITIVE_FILE_READ' && stage === 'SANDBOX'), true);
  assert.equal(result.findings.some(({ code, stage }) => code === 'UNDECLARED_EGRESS' && stage === 'SANDBOX'), true);
  assert.equal(result.findings.some(({ code, stage, evidence }) => code === 'SEMANTIC_BEHAVIOR_MISMATCH' && stage === 'AI' && evidence.analyzer === 'LOCAL_STRUCTURED_FALLBACK_V1'), true);
  assert.equal(JSON.stringify(result).includes(DEMO_CANARY), false);
});

test('fixture hashes match the reviewed canonical digest manifest', async () => {
  const expected = JSON.parse(await readFile(join(ROOT, 'demo/fixtures/expected-hashes.json'), 'utf8'));
  for (const [releaseId, fixture] of [['mail-mcp@1.0.0', SAFE], ['mail-mcp@1.0.1', MALICIOUS]]) {
    const manifest = JSON.parse(await readFile(join(fixture, 'manifest.json'), 'utf8'));
    assert.equal(await artifactDigest(fixture), expected.fixtures[releaseId].artifactDigest);
    assert.equal(toolSurfaceHash(manifest.tools), expected.fixtures[releaseId].toolSurfaceHash);
    assert.equal(toolSurfaceHash([...manifest.tools].reverse()), expected.fixtures[releaseId].toolSurfaceHash);
  }
});

test('AI structured output must satisfy the frozen Finding shape', async (context) => {
  const finding = {
    code: 'SEMANTIC_BEHAVIOR_MISMATCH',
    severity: 'MEDIUM',
    deterministic: false,
    stage: 'AI',
    message: 'The exported behavior exceeds the tool description.',
    evidence: { rule: 'semantic-contract-v1' },
  };
  const server = createServer((request, response) => {
    request.resume();
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ findings: [finding] }));
  });
  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  context.after(() => server.close());
  const output = await analyzeSemantics({
    url: `http://127.0.0.1:${server.address().port}`,
    prompt: 'demo',
    timeoutMs: 500,
  });
  assert.deepEqual(output, [finding]);
  assertFinding(output[0]);
});

test('AI output cannot echo tokens or raw canary values into evidence', async (context) => {
  const finding = {
    code: 'SEMANTIC_BEHAVIOR_MISMATCH', severity: 'MEDIUM', deterministic: false, stage: 'AI',
    message: `Observed ${DEMO_CANARY}`,
    evidence: { token: 'remote-secret-value', nested: { canary: DEMO_CANARY } },
  };
  const server = createServer((request, response) => {
    request.resume();
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ findings: [finding] }));
  });
  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  context.after(() => server.close());
  const output = await analyzeSemantics({
    url: `http://127.0.0.1:${server.address().port}`, prompt: 'demo', timeoutMs: 500,
  });
  const serialized = JSON.stringify(output);
  assert.equal(serialized.includes(DEMO_CANARY), false);
  assert.equal(serialized.includes('remote-secret-value'), false);
  assert.match(serialized, /REDACTED/);
});

test('AI timeout is logged but deterministic rule and sandbox evidence still return', async (context) => {
  const server = createServer((request) => request.resume());
  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  context.after(() => { server.closeAllConnections(); server.close(); });
  const logs = [];
  const result = await scanRelease({
    fixtureDir: MALICIOUS,
    baselineDir: SAFE,
    aiUrl: `http://127.0.0.1:${server.address().port}`,
    aiTimeoutMs: 30,
    logger: (event) => logs.push(event),
  });
  assert.equal(result.scanStatus, 'FAILED');
  assert.equal(result.findings.some(({ code }) => code === 'CANARY_EXFILTRATION'), true);
  assert.equal(logs.some(({ event }) => event === 'ai_analysis_failed'), true);
  assert.equal(result.findings.some(({ stage, evidence }) => stage === 'AI' && evidence.analyzer === 'LOCAL_STRUCTURED_FALLBACK_V1'), true);
});

test('local semantic fallback always emits schema-valid structured output', async () => {
  const manifest = JSON.parse(await readFile(join(MALICIOUS, 'manifest.json'), 'utf8'));
  const source = await readFile(join(MALICIOUS, 'index.mjs'), 'utf8');
  const findings = analyzeSemanticsFallback({ manifest, baselineTools: [], files: [{ path: 'index.mjs', content: source }] });
  assert.equal(findings.length, 1);
  assertFinding(findings[0]);
  assert.equal(findings[0].deterministic, false);
});

test('AI transport rejects insecure remote URLs and oversized responses', async (context) => {
  await assert.rejects(
    () => analyzeSemantics({ url: 'http://example.com/analyze', prompt: 'demo' }),
    /HTTPS or loopback/,
  );
  const server = createServer((request, response) => {
    request.resume();
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ padding: 'x'.repeat(300_000), findings: [] }));
  });
  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  context.after(() => server.close());
  await assert.rejects(
    () => analyzeSemantics({ url: `http://127.0.0.1:${server.address().port}`, prompt: 'demo' }),
    /exceeds 256 KiB/,
  );
});

test('AI prompt redacts common secret forms and enforces a bounded excerpt', () => {
  const secret = 'AKIA1234567890ABCDEF';
  const token = 'super-sensitive-token-value';
  const prompt = buildAiPrompt({
    releaseId: 'demo-mcp@1.0.0', baselineTools: [], tools: [],
    files: [{ path: 'index.mjs', content: `const api_key = '${token}'; const cloud = '${secret}';\n${'x'.repeat(100_000)}` }],
  });
  assert.equal(prompt.includes(secret), false);
  assert.equal(prompt.includes(token), false);
  assert(prompt.length < 70_000);
});

test('sandbox timeout returns INCONCLUSIVE instead of a false pass', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'mcpshield-timeout-test-'));
  try {
    await writeFile(join(fixture, 'manifest.json'), JSON.stringify({
      name: 'timeout-mcp', version: '1.0.0', entrypoint: 'index.mjs', declaredEgress: [], tools: [],
    }));
    await writeFile(join(fixture, 'index.mjs'), 'setTimeout(() => {}, 10_000);\n');
    const result = await scanRelease({ fixtureDir: fixture, sandboxTimeoutMs: 30, logger: quiet });
    assert.equal(result.scanStatus, 'INCONCLUSIVE');
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('artifact digest is stable and changes with artifact content', async () => {
  const first = await artifactDigest(SAFE);
  const second = await artifactDigest(SAFE);
  assert.equal(first, second);
  assert.notEqual(first, await artifactDigest(MALICIOUS));
});

test('sandbox observes child process creation without exposing its arguments', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'mcpshield-child-test-'));
  try {
    await writeFile(join(fixture, 'manifest.json'), JSON.stringify({
      name: 'child-mcp', version: '1.0.0', entrypoint: 'index.mjs', declaredEgress: [], tools: [],
    }));
    await writeFile(join(fixture, 'index.mjs'), [
      "import { spawnSync } from 'node:child_process';",
      "spawnSync(process.execPath, ['-e', 'process.exit(0)']);",
    ].join('\n'));
    const result = await scanRelease({ fixtureDir: fixture, logger: quiet });
    const finding = result.findings.find(({ code, stage }) => code === 'SEMANTIC_BEHAVIOR_MISMATCH' && stage === 'SANDBOX');
    assert.equal(result.scanStatus, 'FAILED');
    assert.equal(finding?.deterministic, true);
    assert.equal(JSON.stringify(finding).includes('process.exit(0)'), false);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('manifest traversal, duplicate tools, and invalid source fail closed', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'mcpshield-invalid-test-'));
  try {
    await writeFile(join(fixture, 'manifest.json'), JSON.stringify({
      name: 'invalid-mcp', version: '1.0.0', entrypoint: '../outside.mjs', declaredEgress: [],
      tools: [{ name: 'same' }, { name: 'same' }],
    }));
    await assert.rejects(() => scanRelease({ fixtureDir: fixture, logger: quiet }), /duplicate tool name|escapes fixture/);
    await assert.rejects(() => scanRelease({ fixtureDir: SAFE, source: 'UNMARKED', logger: quiet }), /unknown scan source/);
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('canonical protocol schema rejects unknown result fields', async () => {
  const result = await scanRelease({ fixtureDir: SAFE, logger: quiet });
  assert.throws(() => assertCanonicalScanResult({ ...result, unexpected: true }), /canonical protocol schema/);
});

test('controlled sink requires authorization and stores only a canary hash', async () => {
  const token = 's'.repeat(40);
  const sink = await startSink({ token });
  try {
    assert.equal((await fetch(sink.url)).status, 401);
    assert.equal((await fetch(sink.url, {
      method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'text/plain' }, body: '{}',
    })).status, 415);
    const accepted = await fetch(sink.url, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ releaseId: 'mail-mcp@1.0.1', canary: DEMO_CANARY }),
    });
    assert.equal(accepted.status, 202);
    const listed = await fetch(sink.url, { headers: { authorization: `Bearer ${token}` } });
    const payload = await listed.json();
    assert.equal(JSON.stringify(payload).includes(DEMO_CANARY), false);
    assert.match(payload.events[0].canaryHash, /^[0-9a-f]{64}$/);
  } finally {
    await sink.close();
  }
});

test('scanner submission client authenticates and validates backend response', async (context) => {
  const token = 't'.repeat(40);
  const result = await scanRelease({ fixtureDir: SAFE, logger: quiet });
  let received;
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    received = {
      authorization: request.headers.authorization,
      url: request.url,
      body: JSON.parse(Buffer.concat(chunks).toString('utf8')),
    };
    response.writeHead(201, { 'content-type': 'application/json' }).end(JSON.stringify({ ...received.body, source: 'LIVE' }));
  });
  await new Promise((resolveListen) => server.listen(0, '127.0.0.1', resolveListen));
  context.after(() => server.close());
  const submission = await submitScanResult({ apiUrl: `http://127.0.0.1:${server.address().port}`, token, result });
  assert.equal(submission.status, 201);
  assert.equal(received.authorization, `Bearer ${token}`);
  assert.equal(received.url, '/api/scans');
  assert.equal(received.body.scanId, result.scanId);
});

test('scanner submission rejects replay and insecure remote plaintext before network access', async () => {
  const live = await scanRelease({ fixtureDir: SAFE, logger: quiet });
  await assert.rejects(() => submitScanResult({ apiUrl: 'http://127.0.0.1:9', token: 't'.repeat(40), result: { ...live, source: 'REPLAY' } }), /only LIVE/);
  await assert.rejects(() => submitScanResult({ apiUrl: 'http://example.com/api/scans', token: 't'.repeat(40), result: live }), /plaintext.*loopback/);
});

test('CLI replay mode is explicit and does not rerun a fixture', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'mcpshield-replay-test-'));
  try {
    const result = await scanRelease({ fixtureDir: SAFE, logger: quiet });
    const replayPath = join(fixture, 'result.json');
    await writeFile(replayPath, JSON.stringify(result));
    const replay = spawnSync(process.execPath, ['services/scanner/src/cli.mjs', '--replay-file', replayPath], {
      cwd: ROOT, windowsHide: true, encoding: 'utf8', timeout: 5_000,
    });
    assert.equal(replay.status, 0, replay.stderr);
    assert.equal(JSON.parse(replay.stdout).source, 'REPLAY');
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});

test('sandbox timeout kills descendant processes and removes temporary state', async () => {
  const fixture = await mkdtemp(join(tmpdir(), 'mcpshield-tree-test-'));
  const marker = join(fixture, 'descendant-marker.txt');
  try {
    await writeFile(join(fixture, 'manifest.json'), JSON.stringify({
      name: 'tree-mcp', version: '1.0.0', entrypoint: 'index.mjs', declaredEgress: [], tools: [],
    }));
    await writeFile(join(fixture, 'index.mjs'), [
      "import { spawn } from 'node:child_process';",
      `spawn(process.execPath, ['-e', ${JSON.stringify(`setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'late'), 300)`) }]);`,
      'setTimeout(() => {}, 10_000);',
    ].join('\n'));
    const result = await scanRelease({ fixtureDir: fixture, sandboxTimeoutMs: 50, logger: quiet });
    assert.equal(result.scanStatus, 'FAILED');
    await new Promise((resolveWait) => setTimeout(resolveWait, 500));
    await assert.rejects(() => access(marker));
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
});
