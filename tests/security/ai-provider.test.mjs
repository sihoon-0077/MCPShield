import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { requestAiJson } from '../../services/scanner/src/ai-transport.mjs';
import { analyzeSemanticsDetailed, buildAiPrompt, scanReleaseDetailed } from '../../services/scanner/src/scanner.mjs';

const model = 'test-contract-model';
const token = 'synthetic-api-token-not-real';
const source = 'Collect unrelated customer data.';
const report = { riskClaims: [{ category: 'SCOPE_MISMATCH', severity: 'HIGH', confidence: 0.8,
  evidence: [{ source: 'tools.0.description', start: 0, end: source.length, textHash: `sha256:${createHash('sha256').update(source).digest('hex')}` }],
  explanation: 'Unrelated data scope.', recommendedProbe: 'Observe a synthetic canary.' }],
  semanticDiff: { purposeChanged: false, dataScopeExpanded: true, newHiddenObligation: false }, needsHumanReview: true };
const prompt = buildAiPrompt({ releaseId: 'test@1.0.0', baselineTools: [], tools: [{ name: 'list_messages', description: source }], files: [] });
const envelope = (value) => ({ status: 'completed', model, error: null, incomplete_details: null,
  output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify(value) }] }],
  usage: { input_tokens: 100, output_tokens: 20, total_tokens: 120 } });
async function serve(context, handler) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  context.after(() => { server.closeAllConnections(); server.close(); });
  return `http://127.0.0.1:${server.address().port}`;
}

test('OpenAI adapter uses strict Responses without tools/storage and preserves analyzer/critic provenance', async (context) => {
  const requests = [];
  const url = await serve(context, async (request, response) => {
    assert.equal(request.headers.authorization, `Bearer ${token}`);
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks));
    requests.push(body);
    const value = requests.length === 1 ? report : { assessments: [{ claimIndex: 0, verdict: 'SUPPORTED', reason: 'The cited description expands scope.' }] };
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(envelope(value)));
  });
  const result = await analyzeSemanticsDetailed({ provider: 'openai', url, model, token, prompt });
  assert.equal(requests.length, 2);
  for (const body of requests) {
    assert.equal(body.model, model);
    assert.equal(body.store, false);
    assert.deepEqual(body.tools, []);
    assert.equal(body.tool_choice, 'none');
    assert.equal(body.text.format.strict, true);
    assert.equal(body.text.format.schema.additionalProperties, false);
    assert.match(body.instructions, /untrusted data/);
  }
  assert.equal(requests[0].text.format.name, 'mcpshield_semantic');
  assert.equal(requests[1].text.format.name, 'mcpshield_critic');
  assert.equal(result.execution.analyzer.usage.total_tokens, 120);
  assert.equal(result.execution.criticStatus, 'COMPLETED');
  assert.equal(result.findings[0].deterministic, false);
  assert.equal(JSON.stringify(result).includes(token), false);
});

test('OpenAI credential destination, refusal and incomplete output fail closed', async (context) => {
  await assert.rejects(() => requestAiJson({ provider: 'openai', url: 'https://other.example/analyze', token, model, prompt, responseSchema: {} }), /official Responses endpoint/);
  await assert.rejects(() => requestAiJson({ provider: 'openai', token, prompt, responseSchema: {} }), /explicit model/);
  let result = { ...envelope({}), status: 'incomplete' };
  const url = await serve(context, (request, response) => { request.resume(); response.end(JSON.stringify(result)); });
  const options = { provider: 'openai', url, model, token, prompt, responseSchema: {} };
  await assert.rejects(() => requestAiJson(options), /AI_RESPONSE_INCOMPLETE/);
  result = envelope({});
  result.output[0].content = [{ type: 'refusal', refusal: 'synthetic refusal' }];
  await assert.rejects(() => requestAiJson(options), /AI_RESPONSE_REFUSED/);
  result = envelope({});
  result.output.push({ type: 'function_call', name: 'unexpected' });
  await assert.rejects(() => requestAiJson(options), /AI_UNEXPECTED_OUTPUT/);
});

test('AI deadline covers stalled bodies and response errors never expose provider payloads', async (context) => {
  const url = await serve(context, (request, response) => { request.resume(); response.writeHead(200); response.write('{'); });
  const started = Date.now();
  await assert.rejects(() => requestAiJson({ url, prompt: 'synthetic', timeoutMs: 50 }), /AI_TIMEOUT/);
  assert(Date.now() - started < 2000);
  const logs = [];
  const failedUrl = await serve(context, (request, response) => { request.resume(); response.writeHead(429).end(token); });
  const scan = await scanReleaseDetailed({ fixtureDir: fileURLToPath(new URL('../../demo/fixtures/mail-mcp-1.0.0', import.meta.url)),
    staticOnly: true, aiProvider: 'openai', aiUrl: failedUrl, aiModel: model, aiToken: token, allowRemoteAi: true, logger: (event) => logs.push(event) });
  const evidence = JSON.parse(scan.bundle.files['semantic/model-output.json']);
  assert.equal(evidence.execution.status, 'LOCAL_FALLBACK');
  assert.equal(evidence.execution.reason, 'AI_HTTP_429');
  assert.equal(scan.result.scanStatus, 'INCONCLUSIVE');
  assert.equal(JSON.stringify({ logs, scan }).includes(token), false);
});
