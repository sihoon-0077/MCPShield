import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:http';
import { createEvalAiAdapter, toChatCompletions } from '../../benchmarks/eval40/ai-adapter.mjs';
import { requestAiJson } from '../../services/scanner/src/ai-transport.mjs';
import { semanticOutputSchema } from '../../services/scanner/src/semantic.mjs';

const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`)));
const close = (server) => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); });

test('eval40 adapter: unchanged scanner transport reaches a chat-completions upstream; keys, quota and format failures stay visible', async () => {
  const seen = [];
  let plan = [];
  const upstream = createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    seen.push({ at: Date.now(), authorization: request.headers.authorization, body: JSON.parse(Buffer.concat(chunks).toString()) });
    const step = plan.shift() ?? { status: 200, content: '{"riskClaims":[],"semanticDiff":{"purposeChanged":false,"dataScopeExpanded":false,"newHiddenObligation":false},"needsHumanReview":false}' };
    if (step.status !== 200) { response.writeHead(step.status, { 'retry-after': String(step.retryAfter ?? 0), 'x-ratelimit-remaining-requests': '0' }).end('quota'); return; }
    response.writeHead(200, { 'content-type': 'application/json', 'x-ratelimit-remaining-requests': '149' }).end(JSON.stringify({
      model: 'upstream-model', choices: [{ finish_reason: step.finish ?? 'stop', message: { role: 'assistant', content: step.content } }],
      usage: { prompt_tokens: 11, completion_tokens: 7, total_tokens: 18 } }));
  });
  const upstreamUrl = await listen(upstream);
  const token = 'adapter-token-for-test-only';
  const { server, stats } = createEvalAiAdapter({ token, keys: { 'test-model': 'UPSTREAM-SECRET-KEY' },
    upstreams: { 'test-model': { provider: 'mock', url: `${upstreamUrl}/chat/completions`, model: 'vendor/model-x', minIntervalMs: 300, maxOutputTokens: 1000, headers: {} } } });
  const adapterUrl = `${await listen(server)}/v1/responses`;
  const call = (overrides = {}) => requestAiJson({ provider: 'openai', url: adapterUrl, token, model: 'test-model', prompt: 'synthetic prompt',
    responseSchema: semanticOutputSchema, schemaName: 'mcpshield_semantic', timeoutMs: 10_000, ...overrides });
  try {
    const first = await call();
    assert.deepEqual(first.payload.riskClaims, []);
    assert.deepEqual(first.metadata.usage, { input_tokens: 11, output_tokens: 7, total_tokens: 18 });
    const sent = seen[0];
    assert.equal(sent.authorization, 'Bearer UPSTREAM-SECRET-KEY', 'the upstream gets the provider key, not the adapter token');
    assert.equal(sent.body.model, 'vendor/model-x');
    assert.equal(sent.body.max_tokens, 1000, 'the per-request output ceiling of the upstream wins');
    assert.deepEqual(sent.body.messages.map((m) => m.role), ['system', 'user']);
    assert.equal(sent.body.messages[1].content, 'synthetic prompt');
    assert.equal(sent.body.response_format.type, 'json_schema');
    assert.equal(sent.body.response_format.json_schema.strict, true);
    assert.equal(sent.body.response_format.json_schema.schema.$schema, undefined);
    assert.deepEqual(sent.body.response_format.json_schema.schema.required, semanticOutputSchema.required);

    // Pacing: the next request waits for the minimum interval.
    await call();
    assert.ok(seen[1].at - seen[0].at >= 280, `paced ${seen[1].at - seen[0].at} ms`);

    // Output is passed through untouched: a fenced or truncated answer is still a format failure.
    plan = [{ status: 200, content: '```json\n{}\n```' }];
    await assert.rejects(call(), /AI_INVALID_JSON/);
    plan = [{ status: 200, content: '{"riskClaims":[', finish: 'length' }];
    await assert.rejects(call(), /AI_RESPONSE_INCOMPLETE/);

    // A short per-minute 429 is retried once; a long one (daily quota) comes back as HTTP 429.
    plan = [{ status: 429, retryAfter: 0 }];
    await call();
    assert.equal(stats['test-model'].retries, 1);
    plan = [{ status: 429, retryAfter: 3600 }];
    await assert.rejects(call(), /AI_HTTP_429/);
    assert.equal(stats['test-model'].rateHeaders['x-ratelimit-remaining-requests'], '0');

    // Wrong adapter token and unknown alias are refused before any upstream call.
    const before = seen.length;
    await assert.rejects(call({ token: 'wrong-token-of-same-size-xx' }), /AI_HTTP_401/);
    await assert.rejects(call({ model: 'other-model' }), /AI_HTTP_404/);
    assert.equal(seen.length, before);
    assert.ok(!JSON.stringify(stats).includes('UPSTREAM-SECRET-KEY'), 'stats never hold the key');
  } finally { await close(server); await close(upstream); }
});

test('eval40 adapter: a 503 gets spaced retries within the scanner timeout budget; a refused critic call is counted', async () => {
  const seen = [];
  let plan = [];
  const upstream = createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    seen.push(Date.now());
    const step = plan.shift() ?? { status: 200 };
    if (step.status !== 200) { response.writeHead(step.status).end('high demand'); return; }
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ choices: [{ finish_reason: 'stop',
      message: { role: 'assistant', content: '{"riskClaims":[],"semanticDiff":{"purposeChanged":false,"dataScopeExpanded":false,"newHiddenObligation":false},"needsHumanReview":false}' } }] }));
  });
  const upstreamUrl = await listen(upstream);
  const token = 'adapter-token-for-test-only';
  const base = { provider: 'mock', url: `${upstreamUrl}/chat/completions`, model: 'vendor/model-x', minIntervalMs: 0, headers: {} };
  const { server, stats } = createEvalAiAdapter({ token, keys: { roomy: 'UPSTREAM-SECRET-KEY', tight: 'UPSTREAM-SECRET-KEY' }, upstreams: {
    roomy: { ...base, overloadRetryMs: [40, 80, 120], retryBudgetMs: 5_000 }, tight: { ...base, overloadRetryMs: [400], retryBudgetMs: 300 } } });
  const adapterUrl = `${await listen(server)}/v1/responses`;
  const call = (model, schemaName = 'mcpshield_semantic') => requestAiJson({ provider: 'openai', url: adapterUrl, token, model, prompt: 'synthetic prompt',
    responseSchema: semanticOutputSchema, schemaName, timeoutMs: 10_000 });
  try {
    // Two 503s, then an answer: the caller never sees the overload, and the retries are spaced as configured.
    plan = [{ status: 503 }, { status: 503 }];
    await call('roomy');
    assert.equal(seen.length, 3);
    assert.ok(seen[1] - seen[0] >= 35 && seen[2] - seen[1] >= 75, `spaced ${seen[1] - seen[0]} / ${seen[2] - seen[1]} ms`);
    assert.equal(stats.roomy.retries, 2);

    // Retries run out: the 503 comes back, and only a refused critic call counts as criticLost.
    plan = [{ status: 503 }, { status: 503 }, { status: 503 }, { status: 503 }];
    await assert.rejects(call('roomy'), /AI_HTTP_503/);
    assert.equal(seen.length, 7, 'one first attempt and three retries');
    assert.equal(stats.roomy.criticLost, 0, 'an analyzer refusal is not a lost critic call');
    plan = [{ status: 503 }, { status: 503 }, { status: 503 }, { status: 503 }];
    await assert.rejects(call('roomy', 'mcpshield_critic'), /AI_HTTP_503/);
    assert.equal(stats.roomy.criticLost, 1);

    // A retry that would end past the budget is not started.
    plan = [{ status: 503 }];
    await assert.rejects(call('tight'), /AI_HTTP_503/);
    assert.equal(seen.length, 12);
    assert.equal(stats.tight.retries, 0);
  } finally { await close(server); await close(upstream); }
});

test('eval40 adapter: provider schema relaxation drops keywords, never property names', () => {
  const schema = { type: 'object', additionalProperties: false, required: ['minimum', 'items'], properties: {
    minimum: { type: 'integer', minimum: 1 }, items: { type: 'array', maxItems: 2, items: { type: 'string', maxLength: 5, enum: ['a', 'b'] } } } };
  const body = toChatCompletions({ instructions: 's', input: [{ role: 'user', content: 'u' }], text: { format: { type: 'json_schema', name: 'n', strict: true, schema } } },
    { model: 'm', stripSchemaKeys: ['minimum', 'maxLength', 'maxItems'] });
  assert.deepEqual(body.response_format.json_schema.schema, { type: 'object', additionalProperties: false, required: ['minimum', 'items'], properties: {
    minimum: { type: 'integer' }, items: { type: 'array', items: { type: 'string', enum: ['a', 'b'] } } } });
});
