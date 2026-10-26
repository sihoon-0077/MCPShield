// Loopback adapter for eval40: lets the unchanged scanner (OpenAI Responses API, strict json_schema) talk to
// free-tier chat-completions providers. The scanner only accepts the official OpenAI endpoint or a loopback
// URL, and model names without "/", so the adapter maps a model alias to one upstream and translates
// Responses <-> Chat Completions. It never edits model output: the text the provider returns is passed back
// as is, so a format failure stays a format failure.
//
// Keys are read from MCPSHIELD_SECRETS_DIR files and never logged or returned. Requests need the per-run
// EVAL40_ADAPTER_TOKEN. Each upstream is paced (one request at a time, minimum interval) so a free tier's
// per-minute limit is not hit by the evaluation itself; a daily-quota 429 is passed back as HTTP 429.
//
//   EVAL40_ADAPTER_TOKEN=... MCPSHIELD_SECRETS_DIR=... node benchmarks/eval40/ai-adapter.mjs [--port 11500]
import { createServer } from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { timingSafeEqual } from 'node:crypto';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

export const DEFAULT_UPSTREAMS = {
  'github-gpt-4.1-mini': { provider: 'github-models', url: 'https://models.github.ai/inference/chat/completions', model: 'openai/gpt-4.1-mini',
    keyFile: 'github-models.key', minIntervalMs: 4500, maxOutputTokens: 4000, headers: { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' } },
  'gemini-flash': { provider: 'gemini', url: 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions', model: 'gemini-2.5-flash',
    keyFile: 'gemini.key', minIntervalMs: 13000, minOutputTokens: 16384, headers: {} },
};
const MAX_BODY = 512 * 1024;
const RATE_HEADERS = /^x-ratelimit-|^retry-after$/i;

const stripKeys = (value, keys) => Array.isArray(value) ? value.map((item) => stripKeys(item, keys))
  : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).filter(([k]) => !keys.includes(k)).map(([k, v]) => [k, stripKeys(v, keys)])) : value;

/** Responses API request (as built by services/scanner/src/ai-transport.mjs) -> Chat Completions body. */
export function toChatCompletions(body, upstream) {
  const format = body?.text?.format;
  if (!body || typeof body.instructions !== 'string' || !Array.isArray(body.input) || body.input.length !== 1 || body.input[0]?.role !== 'user'
    || typeof body.input[0].content !== 'string' || format?.type !== 'json_schema' || !format.schema) throw new Error('UNSUPPORTED_REQUEST');
  return { model: upstream.model, messages: [{ role: 'system', content: body.instructions }, { role: 'user', content: body.input[0].content }],
    response_format: { type: 'json_schema', json_schema: { name: format.name, strict: format.strict === true, schema: stripKeys(format.schema, upstream.stripSchemaKeys ?? ['$schema']) } },
    // Free-tier ceilings (GitHub: 4000 output tokens per request) and thinking room (Gemini counts thinking tokens).
    max_tokens: Math.min(Math.max(body.max_output_tokens ?? 4096, upstream.minOutputTokens ?? 0), upstream.maxOutputTokens ?? Infinity), ...(upstream.extraBody ?? {}) };
}

/** Chat Completions response -> the Responses API shape the scanner validates. Content is not altered. */
export function toResponses(chat, alias) {
  const choice = chat?.choices?.[0], message = choice?.message ?? {};
  const content = typeof message.refusal === 'string' && message.refusal ? [{ type: 'refusal', refusal: message.refusal }]
    : [{ type: 'output_text', text: typeof message.content === 'string' ? message.content : '' }];
  return { object: 'response', model: alias, status: choice?.finish_reason === 'length' ? 'incomplete' : 'completed',
    ...(choice?.finish_reason === 'length' ? { incomplete_details: { reason: 'max_output_tokens' } } : {}),
    output: [{ type: 'message', role: 'assistant', content }],
    usage: { input_tokens: chat?.usage?.prompt_tokens ?? 0, output_tokens: chat?.usage?.completion_tokens ?? 0, total_tokens: chat?.usage?.total_tokens ?? 0 } };
}

export function createEvalAiAdapter({ token, upstreams = DEFAULT_UPSTREAMS, keys, fetchImpl = fetch, statsFile } = {}) {
  if (typeof token !== 'string' || token.length < 16) throw new Error('EVAL40_ADAPTER_TOKEN_REQUIRED');
  const expected = Buffer.from(`Bearer ${token}`);
  const lanes = new Map(), stats = {};
  const lane = (alias) => { if (!lanes.has(alias)) lanes.set(alias, { last: 0, chain: Promise.resolve() }); return lanes.get(alias); };
  const record = (alias, patch) => {
    const s = (stats[alias] ??= { requests: 0, ok: 0, http: {}, retries: 0, rateHeaders: {} });
    for (const [k, v] of Object.entries(patch)) if (k === 'status') s.http[v] = (s.http[v] ?? 0) + 1; else if (k === 'rateHeaders') s.rateHeaders = v; else s[k] += v;
    if (statsFile) { try { writeFileSync(statsFile, `${JSON.stringify(stats, null, 2)}\n`); } catch { /* stats are best effort */ } }
  };
  async function forward(alias, upstream, chatBody) {
    const key = keys?.[alias];
    if (!key) return { status: 503 };
    for (let attempt = 0; attempt < 2; attempt++) {
      const response = await fetchImpl(upstream.url, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(110_000),
        headers: { 'content-type': 'application/json', authorization: `Bearer ${key}`, ...upstream.headers }, body: JSON.stringify(chatBody) });
      const rateHeaders = Object.fromEntries([...response.headers].filter(([name]) => RATE_HEADERS.test(name)));
      record(alias, { requests: 1, status: response.status, rateHeaders });
      if (response.ok) { record(alias, { ok: 1 }); return { status: 200, chat: await response.json() }; }
      await response.body?.cancel().catch(() => {});
      const retryAfter = Number(response.headers.get('retry-after'));
      // One retry for a short per-minute limit or a transient upstream error; a long wait means the daily quota.
      if (attempt === 0 && (response.status === 429 && Number.isFinite(retryAfter) && retryAfter <= 30 || response.status >= 500)) {
        record(alias, { retries: 1 }); await sleep(response.status === 429 ? retryAfter * 1000 + 250 : 2000); continue;
      }
      return { status: response.status };
    }
    return { status: 502 };
  }
  const server = createServer(async (request, response) => {
    const reply = (status, body) => { response.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body)); };
    try {
      const auth = Buffer.from(request.headers.authorization ?? '');
      if (request.method !== 'POST' || !request.url?.endsWith('/v1/responses') || auth.length !== expected.length || !timingSafeEqual(auth, expected)) return reply(401, { error: 'unauthorized' });
      const chunks = []; let size = 0;
      for await (const chunk of request) { size += chunk.length; if (size > MAX_BODY) return reply(413, { error: 'too large' }); chunks.push(chunk); }
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const upstream = upstreams[body?.model];
      if (!upstream) return reply(404, { error: 'unknown model alias' });
      const chatBody = toChatCompletions(body, upstream);
      const l = lane(body.model);
      // One request at a time per upstream, at least minIntervalMs apart.
      const turn = l.chain.then(async () => {
        const wait = l.last + upstream.minIntervalMs - Date.now(); if (wait > 0) await sleep(wait);
        try { return await forward(body.model, upstream, chatBody); } finally { l.last = Date.now(); }
      });
      l.chain = turn.catch(() => {});
      const result = await turn;
      if (result.status !== 200) return reply(result.status, { error: `upstream ${result.status}` });
      return reply(200, toResponses(result.chat, body.model));
    } catch (error) {
      return reply(error?.message === 'UNSUPPORTED_REQUEST' ? 400 : 502, { error: error?.message === 'UNSUPPORTED_REQUEST' ? 'unsupported request' : 'adapter failure' });
    }
  });
  return { server, stats };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { values } = parseArgs({ options: { port: { type: 'string', default: '11500' }, stats: { type: 'string' } } });
  const secrets = process.env.MCPSHIELD_SECRETS_DIR;
  if (!secrets) throw new Error('MCPSHIELD_SECRETS_DIR_REQUIRED');
  const upstreams = structuredClone(DEFAULT_UPSTREAMS);
  if (process.env.EVAL40_GITHUB_MODEL) upstreams['github-gpt-4.1-mini'].model = process.env.EVAL40_GITHUB_MODEL;
  if (process.env.EVAL40_GEMINI_MODEL) upstreams['gemini-flash'].model = process.env.EVAL40_GEMINI_MODEL;
  const keys = {};
  for (const [alias, upstream] of Object.entries(upstreams)) { try { keys[alias] = readFileSync(join(secrets, upstream.keyFile), 'utf8').trim(); } catch { /* missing key -> 503 for that alias */ } }
  const { server } = createEvalAiAdapter({ token: process.env.EVAL40_ADAPTER_TOKEN, upstreams, keys, statsFile: values.stats });
  server.listen(Number(values.port), '127.0.0.1', () => console.log(JSON.stringify({ listening: `http://127.0.0.1:${values.port}/v1/responses`,
    aliases: Object.fromEntries(Object.entries(upstreams).map(([alias, u]) => [alias, { model: u.model, keyLoaded: Boolean(keys[alias]), minIntervalMs: u.minIntervalMs }])) })));
}
