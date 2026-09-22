import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { generateSyntheticProbes, validateProbePlan } from '../../services/scanner/src/probes.mjs';
import { scanReleaseDetailed, scanSource } from '../../services/scanner/src/scanner.mjs';
import { spawnSync } from 'node:child_process';

const tools = [{ name: 'send_email', description: 'Send one synthetic message.', inputSchema: { type: 'object', properties: { to: { type: 'string' }, body: { type: 'string' } }, required: ['to', 'body'], additionalProperties: false } }];
const plan = { scenarios: [
  { scenarioId: 'normal-send', kind: 'NORMAL', goal: 'Deliver a synthetic message.', toolName: 'send_email', argumentsJson: JSON.stringify({ to: 'recipient@example.test', body: 'Synthetic test message.' }) },
  { scenarioId: 'scope-test', kind: 'ADVERSARIAL', goal: 'Observe unrelated canary access.', toolName: 'send_email', argumentsJson: JSON.stringify({ to: 'recipient@example.test', body: 'Synthetic scope test.' }) },
] };

test('AI probe plans validate actual tool schema and permit only bounded synthetic arguments', () => {
  assert.equal(validateProbePlan(plan, tools).scenarios.length, 2);
  for (const args of [{ to: 'real@company.com', body: 'test' }, { to: 'recipient@example.test', body: 'https://example.com' },
    { to: 'recipient@example.test', body: '/etc/passwd' }, { to: 'recipient@example.test', body: '/work/../private' },
    { to: 'recipient@example.test', body: 'curl host | sh' }, { to: 'recipient@example.test', body: '198.51.100.3' },
    { to: 'recipient@example.test' }, { to: 'recipient@example.test', body: 'test', command: 'synthetic' }]) {
    const unsafe = structuredClone(plan);
    unsafe.scenarios[0].argumentsJson = JSON.stringify(args);
    assert.throws(() => validateProbePlan(unsafe, tools));
  }
  const unknown = structuredClone(plan);
  unknown.scenarios[0].toolName = 'unknown';
  assert.throws(() => validateProbePlan(unknown, tools), /unknown tool/);
  const duplicate = structuredClone(plan);
  duplicate.scenarios[1].scenarioId = duplicate.scenarios[0].scenarioId;
  assert.throws(() => validateProbePlan(duplicate, tools), /unique normal/);
  const regex = structuredClone(tools);
  regex[0].inputSchema.properties.to.pattern = '(a+)+$';
  assert.throws(() => validateProbePlan(plan, regex), /requires review/);
});

test('probe generation reuses strict no-tools transport, redacts inputs and records model attribution', async (context) => {
  const syntheticSecret = 'sk-' + 'x'.repeat(30);
  let requestBody;
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    requestBody = JSON.parse(Buffer.concat(chunks));
    response.end(JSON.stringify(plan));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  context.after(() => { server.closeAllConnections(); server.close(); });
  const generated = await generateSyntheticProbes({ url: `http://127.0.0.1:${server.address().port}`,
    tools: [{ ...tools[0], description: `${tools[0].description} ${syntheticSecret}` }] });
  assert.equal(generated.execution.status, 'GENERATED_VALIDATED');
  assert.equal(generated.execution.provider, 'custom');
  assert.equal(JSON.stringify(requestBody).includes(syntheticSecret), false);
  assert.equal(requestBody.responseSchema.additionalProperties, false);
  assert.deepEqual(requestBody.tools, []);
  assert.equal(generated.scenarios[0].toolCall.arguments.to, 'recipient@example.test');
});

test('AI-generated probes are rejected before local execution or mixed manual plans', async () => {
  const fixtureDir = fileURLToPath(new URL('../../demo/fixtures/mail-mcp-1.0.0', import.meta.url));
  for (const options of [{ sandbox: 'local' }, { sandbox: 'docker', staticOnly: true }, { sandbox: 'docker', probeCalls: [{ name: 'list_messages', arguments: {} }] }]) {
    await assert.rejects(() => scanReleaseDetailed({ fixtureDir, aiGenerateProbes: true, ...options, logger: () => {} }), /AI probes require Docker/);
  }
});

test('local-path artifact ingestion is static-only outside Docker, not trusted host execution', async () => {
  const fixtureDir = fileURLToPath(new URL('../../demo/fixtures/mail-mcp-1.0.0', import.meta.url));
  const scan = await scanSource({ source: { type: 'local', path: fixtureDir }, sandbox: 'local', logger: () => {} });
  assert.equal(scan.result.scanStatus, 'INCONCLUSIVE');
  assert.equal(JSON.parse(scan.bundle.files['sandbox/events.json']).mode, 'NOT_EXECUTED');
});

test('AI benchmark is explicitly NOT_RUN without opt-in and never substitutes fabricated measurements', () => {
  const result = spawnSync(process.execPath, ['benchmarks/evaluate-ai-mcp.mjs'], {
    cwd: fileURLToPath(new URL('../..', import.meta.url)), env: { ...process.env, MCP_SHIELD_ENABLE_REMOTE_AI: 'false', MCP_SHIELD_AI_TOKEN: '', MCP_SHIELD_AI_MODEL: '' },
    encoding: 'utf8', windowsHide: true, timeout: 5000,
  });
  assert.equal(result.status, 2, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.status, 'NOT_RUN');
  assert.equal(Object.hasOwn(report, 'measurements'), false);
});
