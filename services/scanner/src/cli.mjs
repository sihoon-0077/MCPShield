#!/usr/bin/env node
import { resolve } from 'node:path';
import { scanRelease } from './scanner.mjs';

function parseArgs(args) {
  const options = { sandbox: 'local' };
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith('--') || value === undefined) throw new TypeError(`invalid argument: ${key ?? ''}`);
    options[key.slice(2)] = value;
  }
  if (!options.fixture) throw new TypeError('--fixture is required');
  return options;
}

try {
  const args = parseArgs(process.argv.slice(2));
  const result = await scanRelease({
    fixtureDir: resolve(args.fixture),
    baselineDir: args.baseline ? resolve(args.baseline) : undefined,
    sandbox: args.sandbox,
    sandboxTimeoutMs: args['sandbox-timeout-ms'] ? Number(args['sandbox-timeout-ms']) : undefined,
    aiUrl: args['ai-url'] ?? process.env.MCP_SHIELD_AI_URL,
    aiToken: process.env.MCP_SHIELD_AI_TOKEN,
    aiTimeoutMs: args['ai-timeout-ms'] ? Number(args['ai-timeout-ms']) : undefined,
    source: args.source ?? 'LIVE',
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({ event: 'scan_cli_failed', error: error.message })}\n`);
  process.exitCode = 1;
}
