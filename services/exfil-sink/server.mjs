import { createHash } from 'node:crypto';
import { appendFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';

const MAX_BODY_BYTES = 16 * 1024;

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
      response.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}');
      return;
    }
    if (request.method === 'GET' && request.url === '/events') {
      response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ events }));
      return;
    }
    if (request.method !== 'POST' || request.url !== '/events') {
      response.writeHead(404).end();
      return;
    }
    if (request.headers.authorization !== `Bearer ${token}`) {
      response.writeHead(401).end();
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
      events.push(event);
      onEvent?.(event);
      if (eventFile) await appendFile(eventFile, `${JSON.stringify(event)}\n`, { encoding: 'utf8' });
      response.writeHead(202, { 'content-type': 'application/json' }).end('{"accepted":true}');
    } catch (error) {
      response.writeHead(error.statusCode ?? 500).end();
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
