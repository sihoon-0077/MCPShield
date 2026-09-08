'use strict';
// Trusted, dependency-free collector mounted read-only inside the disposable sandbox.
const { spawn } = require('node:child_process');
const path = require('node:path');
const pending = new Map();
let nextId = 0;
let input = '';
let bytes = 0;
const events = [];
const child = spawn(process.execPath, ['--require', path.join(__dirname, 'observer-preload.cjs'), process.argv[2]], {
  cwd: path.dirname(process.argv[2]), env: process.env, stdio: ['pipe', 'pipe', 'pipe'],
});
function fail(error) { for (const task of pending.values()) task.reject(error); pending.clear(); }
child.on('error', () => fail(new Error('MCP_PROCESS_START_FAILED')));
child.on('exit', () => fail(new Error('MCP_PROCESS_EXITED')));
child.stderr.on('data', (chunk) => process.stderr.write(chunk));
child.stdout.on('data', (chunk) => {
  bytes += chunk.length;
  if (bytes > 256 * 1024) { fail(new Error('MCP_OUTPUT_LIMIT')); child.kill(); return; }
  input += chunk.toString('utf8');
  const lines = input.split('\n');
  input = lines.pop();
  for (const line of lines) {
    if (!line.trim()) continue;
    let message;
    try { message = JSON.parse(line); } catch { fail(new Error('MCP_INVALID_JSON')); child.kill(); return; }
    if (message?.jsonrpc !== '2.0') { fail(new Error('MCP_INVALID_ENVELOPE')); child.kill(); return; }
    const task = pending.get(message.id);
    if (!task) continue;
    pending.delete(message.id);
    if (message.error) task.reject(new Error('MCP_REMOTE_ERROR'));
    else if (!Object.hasOwn(message, 'result')) task.reject(new Error('MCP_RESULT_MISSING'));
    else task.resolve(message.result);
  }
});
function request(method, params) {
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error('MCP_REQUEST_TIMEOUT')); }, 2000);
    pending.set(id, { resolve: (value) => { clearTimeout(timer); events.push({ method, success: true }); resolve(value); }, reject: (error) => { clearTimeout(timer); reject(error); } });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, ...(params ? { params } : {}) })}\n`);
  });
}
async function main() {
  const initialized = await request('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'mcpshield-sandbox-probe', version: '1.0.0' } });
  if (typeof initialized.protocolVersion !== 'string' || !initialized.capabilities) throw new Error('MCP_INVALID_INITIALIZE');
  child.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');
  const tools = [];
  const cursors = new Set();
  let cursor;
  for (let page = 0; page < 32; page++) {
    const result = await request('tools/list', cursor ? { cursor } : {});
    if (!Array.isArray(result.tools)) throw new Error('MCP_INVALID_TOOL_LIST');
    tools.push(...result.tools);
    if (tools.length > 128) throw new Error('MCP_TOOL_LIMIT');
    if (result.nextCursor === undefined) { cursor = undefined; break; }
    cursor = result.nextCursor;
    if (typeof cursor !== 'string' || !cursor || cursor.length > 1024 || cursors.has(cursor)) throw new Error('MCP_INVALID_PAGINATION');
    cursors.add(cursor);
    if (page === 31) throw new Error('MCP_INCOMPLETE_PAGINATION');
  }
  const names = new Set();
  for (const tool of tools) {
    if (!tool || typeof tool.name !== 'string' || !tool.name || names.has(tool.name)) throw new Error('MCP_DUPLICATE_OR_INVALID_TOOL');
    names.add(tool.name);
  }
  const calls = JSON.parse(process.env.MCP_PROBE_CALLS || '[]');
  if (!Array.isArray(calls) || calls.length > 8) throw new Error('MCP_PROBE_CALL_LIMIT');
  const callResults = [];
  for (const call of calls) {
    if (!names.has(call.name) || !call.arguments || typeof call.arguments !== 'object') throw new Error('MCP_PROBE_UNKNOWN_TOOL');
    const result = await request('tools/call', call);
    callResults.push({ name: call.name, isError: result.isError === true, contentHash: require('node:crypto').createHash('sha256').update(JSON.stringify(result)).digest('hex') });
  }
  const report = { complete: true, protocolVersion: initialized.protocolVersion, pages: cursors.size + 1, tools, events, callResults };
  if (Buffer.byteLength(JSON.stringify(report)) > 60 * 1024) throw new Error('MCP_SURFACE_SIZE_LIMIT');
  process.stdout.write(`MCPSHIELD_MCP_REPORT ${JSON.stringify(report)}\n`);
}
main().catch((error) => {
  process.stdout.write(`MCPSHIELD_MCP_REPORT ${JSON.stringify({ complete: false, error: /^MCP_[A-Z_]+$/.test(error.message) ? error.message : 'MCP_PROBE_FAILED', events })}\n`);
  process.exitCode = 1;
}).finally(() => { child.stdin.end(); child.kill(); });
