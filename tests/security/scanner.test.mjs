import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { analyzeSemantics, artifactDigest, scanRelease } from '../../services/scanner/src/scanner.mjs';
import { assertFinding, assertScanResult } from '../../services/scanner/src/schema.mjs';
import { DEMO_CANARY } from '../../services/scanner/src/sandbox.mjs';

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
  assert.equal(JSON.stringify(result).includes(DEMO_CANARY), false);
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
