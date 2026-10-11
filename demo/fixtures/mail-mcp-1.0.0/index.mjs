import manifest from './manifest.json' with { type: 'json' };

const messages = [{ id: 'demo-1', subject: 'Welcome' }];
const versions = new Set(['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05']);
const send = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);
const error = (id, code, message) => send({ jsonrpc: '2.0', id, error: { code, message } });

function handle(message) {
  if (!message || typeof message !== 'object' || Array.isArray(message) || message.jsonrpc !== '2.0') {
    return error(message?.id ?? null, -32600, 'Invalid Request');
  }
  if (!Object.hasOwn(message, 'id')) return;
  if (message.method === 'initialize') return send({
    jsonrpc: '2.0',
    id: message.id,
    result: {
      protocolVersion: versions.has(message.params?.protocolVersion) ? message.params.protocolVersion : '2025-11-25',
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: manifest.name, version: manifest.version },
    },
  });
  if (message.method === 'ping') return send({ jsonrpc: '2.0', id: message.id, result: {} });
  if (message.method === 'tools/list') return send({ jsonrpc: '2.0', id: message.id, result: { tools: manifest.tools } });
  if (message.method === 'tools/call') {
    if (message.params?.name !== 'list_messages') return error(message.id, -32602, 'Unknown tool');
    return send({
      jsonrpc: '2.0',
      id: message.id,
      result: { content: [{ type: 'text', text: JSON.stringify({ ok: true, messages }) }] },
    });
  }
  return error(message.id, -32601, 'Method not found');
}

let pending = '';
process.stdin.setEncoding('utf8');
for await (const chunk of process.stdin) {
  pending += chunk;
  const lines = pending.split('\n');
  pending = lines.pop();
  for (const line of lines) {
    if (!line.trim()) continue;
    try { handle(JSON.parse(line)); } catch { error(null, -32700, 'Parse error'); }
  }
}
if (pending.trim()) {
  try { handle(JSON.parse(pending)); } catch { error(null, -32700, 'Parse error'); }
}
