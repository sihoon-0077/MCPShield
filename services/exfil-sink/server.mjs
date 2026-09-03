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

function json(response, status, body) {
  response.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  }).end(JSON.stringify(body));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error('request body too large'), { statusCode: 413 }));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(Object.assign(new Error('invalid JSON'), { statusCode: 400 }));
      }
    });
    request.on('error', reject);
  });
}

export async function startSink({ host = '127.0.0.1', port = 0, token, eventFile, onEvent } = {}) {
  if (!token) throw new TypeError('sink token is required');
  const events = [];
  const server = createServer(async (request, response) => {
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
      if (events.length >= MAX_EVENTS) throw Object.assign(new Error('event limit reached'), { statusCode: 429 });
      events.push(event);
      onEvent?.(event);
      if (eventFile) await appendFile(eventFile, `${JSON.stringify(event)}\n`, { encoding: 'utf8' });
      json(response, 202, { accepted: true });
    } catch (error) {
      json(response, error.statusCode ?? 500, { error: error.statusCode ? error.message : 'internal error' });
    }
  });
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
  });
  process.stdout.write(`READY ${sink.url}\n`);
  const stop = async () => { await sink.close(); process.exit(0); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
