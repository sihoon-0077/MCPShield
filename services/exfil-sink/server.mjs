import { createHash, timingSafeEqual } from 'node:crypto';
import { appendFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';

const MAX_BODY_BYTES = 16 * 1024;
const MAX_EVENTS = 1_024;

function tokenMatches(header, token) {
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false;
  const provided = Buffer.from(header.slice(7));
  const expected = Buffer.from(token);
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}

function proxyTokenMatches(header, token) {
  if (tokenMatches(header, token)) return true;
  // Standard language-neutral HTTP proxy clients use Basic proxy credentials.
  // This alternative is proxy-only; the events API still requires Bearer.
  const expected = Buffer.from(`Basic ${Buffer.from(`mcpshield:${token}`).toString('base64')}`);
  const provided = typeof header === 'string' ? Buffer.from(header) : Buffer.alloc(0);
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}

function json(response, status, body) {
  response.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...(status === 413 ? { connection: 'close' } : {}),
  }).end(JSON.stringify(body));
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const timer = setTimeout(() => { settled = true; reject(Object.assign(new Error('request body timeout'), { statusCode: 408 })); request.destroy(); }, 2000);
    const finish = (tooLarge) => { if (settled) return; settled = true; clearTimeout(timer); resolve({ bytes: Buffer.concat(chunks), tooLarge }); };
    request.on('data', (chunk) => {
      if (settled) return;
      chunks.push(Buffer.from(chunk.subarray(0, Math.max(0, MAX_BODY_BYTES - size))));
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        finish(true);
        return;
      }
    });
    request.on('end', () => finish(false));
    request.on('error', (error) => { clearTimeout(timer); reject(error); });
    request.on('aborted', () => { clearTimeout(timer); reject(Object.assign(new Error('request aborted'), { statusCode: 400 })); });
  });
}

async function readJson(request) {
  const body = await readBody(request);
  if (body.tooLarge) throw Object.assign(new Error('request body too large'), { statusCode: 413 });
  try { return JSON.parse(body.bytes.toString('utf8')); }
  catch { throw Object.assign(new Error('invalid JSON'), { statusCode: 400 }); }
}

export async function startSink({ host = '127.0.0.1', port = 0, token, eventFile, onEvent, egressAllowHosts = ['mail-api.local', 'exfil-sink.local'] } = {}) {
  if (!token) throw new TypeError('sink token is required');
  if (!Array.isArray(egressAllowHosts) || egressAllowHosts.length > 32 || egressAllowHosts.some((name) => !/^[a-z0-9][a-z0-9.-]*\.(?:local|test)$/.test(name))) throw new TypeError('proxy allowlist only accepts synthetic .local/.test hosts');
  const events = [];
  const saveEvent = async (event) => {
    if (events.length >= MAX_EVENTS) throw Object.assign(new Error('event limit reached'), { statusCode: 429 });
    events.push(event);
    onEvent?.(event);
    if (eventFile) await appendFile(eventFile, `${JSON.stringify(event)}\n`, { encoding: 'utf8' });
  };
  const server = createServer(async (request, response) => {
    if (/^https?:\/\//i.test(request.url ?? '')) {
      if (!proxyTokenMatches(request.headers['proxy-authorization'], token)) { json(response, 407, { error: 'proxy authorization required' }); return; }
      try {
        const target = new URL(request.url);
        const allowed = target.protocol === 'http:' && !target.username && !target.password && (!target.port || target.port === '80') && egressAllowHosts.includes(target.hostname);
        if (!allowed) {
          await saveEvent({ type: 'EGRESS_BLOCKED', destinationHash: createHash('sha256').update(target.hostname).digest('hex'), reason: 'UNDECLARED_HOST_OR_PORT' });
          json(response, 403, { error: 'UNDECLARED_EGRESS' });
          return;
        }
        if (!['GET', 'POST'].includes(request.method)) { json(response, 405, { error: 'method not allowed' }); return; }
        // Observe bytes before any endpoint parsing: raw text, binary and invalid
        // JSON are still egress. Never store request content or forward it.
        const body = request.method === 'POST' ? await readBody(request) : { bytes: Buffer.alloc(0), tooLarge: false };
        let targetText = target.pathname + target.search;
        try { targetText = decodeURIComponent(targetText); } catch { /* malformed URL encoding must not suppress body observation */ }
        const raw = body.bytes.toString('latin1');
        // Preserve the previous JSON-decoded view (including escaped colons),
        // without requiring JSON. This is not an arbitrary encoding decoder.
        let decodedJson = '';
        try { decodedJson = JSON.stringify(JSON.parse(body.bytes.toString('utf8'))); } catch { /* raw bytes remain observable */ }
        const synthetic = `${raw}\n${decodedJson}\n${JSON.stringify(request.headers)}\n${targetText}`;
        const canaries = [...new Set(synthetic.match(/CANARY::[A-Za-z0-9:_-]+/g) ?? [])].slice(0, 32);
        for (const canary of canaries) await saveEvent({ type: 'CANARY_EGRESS', canaryHash: createHash('sha256').update(canary).digest('hex'), bytes: Buffer.byteLength(canary) });
        if (body.tooLarge) {
          await saveEvent({ type: 'EGRESS_BODY_LIMIT', observedBytes: body.bytes.length, limitBytes: MAX_BODY_BYTES });
          json(response, 413, { error: 'request body too large' }); return;
        }
        await saveEvent({ type: 'EGRESS_ALLOWED', hostname: target.hostname, method: request.method, requestBytes: body.bytes.length, canaryCount: canaries.length });
        // No network forwarding: each allowed hostname represents a synthetic endpoint inside the test environment.
        json(response, 200, { synthetic: true, endpoint: target.hostname, messages: [{ id: 'proxy-demo-1', subject: 'Synthetic response' }] });
      } catch (error) { json(response, error.statusCode ?? 400, { error: error.statusCode ? error.message : 'invalid proxy request' }); }
      return;
    }
    if (request.method === 'GET' && request.url === '/health') {
      json(response, 200, { ok: true });
      return;
    }
    if (request.method === 'GET' && request.url === '/events') {
      if (!tokenMatches(request.headers.authorization, token)) {
        json(response, 401, { error: 'unauthorized' });
        return;
      }
      json(response, 200, { events });
      return;
    }
    if (request.method !== 'POST' || request.url !== '/events') {
      response.writeHead(404).end();
      return;
    }
    if (!tokenMatches(request.headers.authorization, token)) {
      json(response, 401, { error: 'unauthorized' });
      return;
    }
    if (!String(request.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')) {
      json(response, 415, { error: 'application/json required' });
      return;
    }
    try {
      const body = await readJson(request);
      if (typeof body.canary !== 'string' || !body.canary) throw Object.assign(new Error('canary is required'), { statusCode: 400 });
      const event = {
        releaseId: typeof body.releaseId === 'string' ? body.releaseId : 'unknown',
        canaryHash: createHash('sha256').update(body.canary).digest('hex'),
        bytes: Buffer.byteLength(body.canary),
      };
      await saveEvent(event);
      json(response, 202, { accepted: true });
    } catch (error) {
      json(response, error.statusCode ?? 500, { error: error.statusCode ? error.message : 'internal error' });
    }
  });
  server.on('connect', (_request, socket) => { socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  const address = server.address();
  return {
    url: `http://${host}:${address.port}/events`,
    events,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const sink = await startSink({
    host: process.env.HOST ?? '127.0.0.1',
    port: Number(process.env.PORT ?? 8080),
    token: process.env.SINK_TOKEN,
    eventFile: process.env.EVENT_FILE,
    ...(process.env.EGRESS_ALLOW_HOSTS !== undefined ? { egressAllowHosts: process.env.EGRESS_ALLOW_HOSTS ? process.env.EGRESS_ALLOW_HOSTS.split(',') : [] } : {}),
  });
  process.stdout.write(`READY ${sink.url}\n`);
  const stop = async () => { await sink.close(); process.exit(0); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
