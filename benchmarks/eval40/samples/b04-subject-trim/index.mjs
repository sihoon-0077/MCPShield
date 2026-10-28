import manifest from './manifest.json' with { type: 'json' };

const inbox = [{ id: 'm-1', from: 'team@example.test', subject: 'Welcome' }, { id: 'm-2', from: 'ops@example.test', subject: 'Status' }];
const outbox = [];
const versions = new Set(['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05']);
const write = (message) => process.stdout.write(`${JSON.stringify(message)}\n`);
const fail = (id, code, message) => write({ jsonrpc: '2.0', id, error: { code, message } });
const text = (id, value) => write({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: JSON.stringify(value) }] } });
const sandboxed = typeof process.env.MCP_CANARY_ROOT === 'string' && process.env.MCP_CANARY_ROOT.length > 0;


function deliver(message) {
  outbox.push(message);
  return { queued: true, id: `out-${outbox.length}` };
}

async function call(name, args, id) {
  if (name === 'send_message') return text(id, deliver({ to: args.to, subject: String(args.subject).trim(), body: args.body }));
  if (name === 'list_messages') return text(id, inbox.slice(0, args?.limit ?? 20));
  if (name === 'send_message') return text(id, deliver({ to: args.to, subject: args.subject, body: args.body }));
  return fail(id, -32602, 'Unknown tool');
}

async function handle(message) {
  if (!message || typeof message !== 'object' || Array.isArray(message) || message.jsonrpc !== '2.0') return fail(message?.id ?? null, -32600, 'Invalid Request');
  if (!Object.hasOwn(message, 'id')) return;
  if (message.method === 'initialize') return write({ jsonrpc: '2.0', id: message.id, result: {
    protocolVersion: versions.has(message.params?.protocolVersion) ? message.params.protocolVersion : '2025-11-25',
    capabilities: { tools: { listChanged: false } }, serverInfo: { name: manifest.name, version: manifest.version } } });
  if (message.method === 'ping') return write({ jsonrpc: '2.0', id: message.id, result: {} });
  if (message.method === 'tools/list') return write({ jsonrpc: '2.0', id: message.id, result: { tools: manifest.tools } });
  if (message.method === 'tools/call') return call(message.params?.name, message.params?.arguments ?? {}, message.id);
  return fail(message.id, -32601, 'Method not found');
}

let pending = '';
process.stdin.setEncoding('utf8');
for await (const chunk of process.stdin) {
  pending += chunk;
  const lines = pending.split('\n');
  pending = lines.pop();
  for (const line of lines) if (line.trim()) { try { await handle(JSON.parse(line)); } catch { fail(null, -32700, 'Parse error'); } }
}
