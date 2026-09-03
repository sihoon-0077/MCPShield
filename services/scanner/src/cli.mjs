#!/usr/bin/env node
import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { scanRelease } from './scanner.mjs';
import { assertScanResult } from './schema.mjs';
import { assertCanonicalScanResult } from './protocol-schema.mjs';
import { submitScanResult } from './submit.mjs';

const USAGE = `MCPShield scanner

Live scan:
  node services/scanner/src/cli.mjs --fixture PATH [--baseline PATH] [--sandbox local|docker]

Replay a saved result (never submitted as LIVE):
  node services/scanner/src/cli.mjs --replay-file RESULT.json

Optional live submission:
  --submit-url http://127.0.0.1:3001/api/scans
  SCANNER_API_TOKEN must be set in the environment.

Optional remote AI (explicit opt-in):
  --ai-url https://trusted.example/analyze --allow-remote-ai true
`;

function parseArgs(args) {
  const options = { sandbox: 'local' };
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!key?.startsWith('--') || value === undefined) throw new TypeError(`invalid argument: ${key ?? ''}`);
    options[key.slice(2)] = value;
  }
  if (Boolean(options.fixture) === Boolean(options['replay-file'])) {
    throw new TypeError('provide exactly one of --fixture or --replay-file');
  }
  return options;
}

async function loadReplay(path) {
  const replayPath = resolve(path);
  if ((await stat(replayPath)).size > 256 * 1024) throw new Error('replay file exceeds 256 KiB');
  const parsed = JSON.parse(await readFile(replayPath, 'utf8'));
  const result = { ...parsed, source: 'REPLAY' };
  assertScanResult(result);
  return assertCanonicalScanResult(result);
}

try {
  if (process.argv.includes('--help')) {
    process.stdout.write(USAGE);
    process.exit(0);
  }
  const args = parseArgs(process.argv.slice(2));
  const remoteAiOptIn = args['allow-remote-ai'] ?? process.env.MCP_SHIELD_ENABLE_REMOTE_AI ?? 'false';
  if (!['true', 'false'].includes(remoteAiOptIn)) throw new TypeError('--allow-remote-ai must be true or false');
  const result = args['replay-file']
    ? await loadReplay(args['replay-file'])
    : await scanRelease({
        fixtureDir: resolve(args.fixture),
        baselineDir: args.baseline ? resolve(args.baseline) : undefined,
        sandbox: args.sandbox,
        sandboxTimeoutMs: args['sandbox-timeout-ms'] ? Number(args['sandbox-timeout-ms']) : undefined,
        aiUrl: args['ai-url'] ?? process.env.MCP_SHIELD_AI_URL,
        aiToken: process.env.MCP_SHIELD_AI_TOKEN,
        aiTimeoutMs: args['ai-timeout-ms'] ? Number(args['ai-timeout-ms']) : undefined,
        allowRemoteAi: remoteAiOptIn === 'true',
        source: args.source ?? 'LIVE',
      });
  if (args['submit-url']) {
    const submission = await submitScanResult({
      apiUrl: args['submit-url'],
      token: process.env.SCANNER_API_TOKEN,
      result,
      timeoutMs: args['submit-timeout-ms'] ? Number(args['submit-timeout-ms']) : undefined,
    });
    process.stderr.write(`${JSON.stringify({ event: 'scan_submitted', scanId: result.scanId, status: submission.status, source: result.source })}\n`);
  }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`${JSON.stringify({ event: 'scan_cli_failed', error: error.message })}\n`);
  process.exitCode = 1;
}
