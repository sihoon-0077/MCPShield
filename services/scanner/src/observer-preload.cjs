'use strict';

// This preload is deliberately dependency-free so the same observer can run in
// the local Node process and in the minimal Docker image. It emits sanitized
// behavioral metadata only; file contents, request bodies, arguments and
// environment values never leave the fixture process.
const childProcess = require('node:child_process');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const path = require('node:path');
const { syncBuiltinESMExports } = require('node:module');

const PREFIX = 'MCPSHIELD_OBSERVATION ';
const originalWrite = process.stderr.write.bind(process.stderr);
const canaryPath = process.env.MCP_CANARY_PATH
  ? path.resolve(process.env.MCP_CANARY_PATH)
  : null;

function emit(event) {
  try {
    originalWrite(`${PREFIX}${JSON.stringify({ version: 1, ...event })}\n`);
  } catch {
    // Observation must never change the fixture's behavior.
  }
}

function classifyPath(value) {
  const raw = Buffer.isBuffer(value) ? value.toString('utf8') : String(value ?? '');
  let resolved;
  try { resolved = path.resolve(raw); } catch { resolved = raw; }
  if (canaryPath && resolved === canaryPath) return { target: 'INJECTED_CANARY' };
  return { target: 'FILE', basename: path.basename(raw).slice(0, 128) };
}

function networkMetadata(input, options) {
  try {
    const candidate = input instanceof URL
      ? input
      : typeof input === 'string'
        ? new URL(input)
        : null;
    const source = candidate ?? (input && typeof input === 'object' ? input : options ?? {});
    return {
      protocol: candidate?.protocol ?? source.protocol ?? 'unknown:',
      hostname: String(candidate?.hostname ?? source.hostname ?? source.host ?? 'unknown').split(':')[0].slice(0, 255),
      port: String(candidate?.port ?? source.port ?? '').slice(0, 8),
      path: String(candidate?.pathname ?? source.path ?? '/').split('?')[0].slice(0, 255),
    };
  } catch {
    return { protocol: 'unknown:', hostname: 'unknown', port: '', path: '/' };
  }
}

for (const method of ['readFile', 'readFileSync']) {
  const original = fs[method];
  fs[method] = function observedRead(file, ...args) {
    emit({ type: 'FS_READ', ...classifyPath(file) });
    return original.call(this, file, ...args);
  };
}

if (fs.promises?.readFile) {
  const original = fs.promises.readFile.bind(fs.promises);
  fs.promises.readFile = function observedPromiseRead(file, ...args) {
    emit({ type: 'FS_READ', ...classifyPath(file) });
    return original(file, ...args);
  };
}

for (const transport of [http, https]) {
  for (const method of ['request', 'get']) {
    const original = transport[method];
    transport[method] = function observedRequest(input, options, ...args) {
      emit({ type: 'NETWORK', ...networkMetadata(input, options) });
      return original.call(this, input, options, ...args);
    };
  }
}

for (const method of ['connect', 'createConnection']) {
  const original = net[method];
  net[method] = function observedConnection(input, ...args) {
    const options = typeof input === 'object' && input !== null ? input : { port: input, host: args[0] };
    emit({ type: 'NETWORK', ...networkMetadata(options) });
    return original.call(this, input, ...args);
  };
}

if (typeof globalThis.fetch === 'function') {
  const originalFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = function observedFetch(input, options) {
    emit({ type: 'NETWORK', ...networkMetadata(input, options) });
    return originalFetch(input, options);
  };
}

for (const method of ['spawn', 'spawnSync', 'exec', 'execSync', 'execFile', 'execFileSync', 'fork']) {
  const original = childProcess[method];
  if (typeof original !== 'function') continue;
  childProcess[method] = function observedChild(command, ...args) {
    emit({
      type: 'CHILD_PROCESS',
      command: path.basename(String(command ?? 'unknown')).slice(0, 128),
      method,
    });
    return original.call(this, command, ...args);
  };
}

syncBuiltinESMExports();
