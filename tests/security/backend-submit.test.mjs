import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { buildApp } from '../../apps/api/src/app.js';
import { scanRelease } from '../../services/scanner/src/scanner.mjs';
import { submitScanResult } from '../../services/scanner/src/submit.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const safe = resolve(root, 'demo/fixtures/mail-mcp-1.0.0');
const adminToken = 'admin-security-integration-token-000000';
const scannerToken = 'scanner-security-integration-token-000';

function runScannerCli(args, env) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(process.execPath, ['services/scanner/src/cli.mjs', ...args], {
      cwd: root,
      env: { ...process.env, ...env },
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 10_000);
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`scanner CLI failed (${code}): ${stderr}`));
      else resolveResult({ stdout, stderr });
    });
  });
}

test('scanner submits a canonical LIVE result to the real backend endpoint', async (context) => {
  const app = await buildApp({
    databasePath: ':memory:',
    adminApiToken: adminToken,
    scannerApiToken: scannerToken,
  });
  await app.listen({ host: '127.0.0.1', port: 0 });
  context.after(() => app.close());
  const address = app.server.address();
  assert(address && typeof address !== 'string');
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const result = await scanRelease({ fixtureDir: safe, logger: () => {} });

  const registration = await fetch(`${baseUrl}/api/releases`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${adminToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      schemaVersion: '1.0.0',
      releaseId: result.releaseId,
      artifactDigest: result.artifactDigest,
      toolSurfaceHash: result.toolSurfaceHash,
    }),
  });
  assert.equal(registration.status, 201);

  const cli = await runScannerCli([
    '--fixture', 'demo/fixtures/mail-mcp-1.0.0',
    '--submit-url', baseUrl,
  ], { SCANNER_API_TOKEN: scannerToken });
  const submittedResult = JSON.parse(cli.stdout);
  assert.equal(submittedResult.source, 'LIVE');
  assert.match(cli.stderr, /"event":"scan_submitted"/);

  const stored = await (await fetch(`${baseUrl}/api/scans/${submittedResult.scanId}`)).json();
  assert.equal(stored.scanId, submittedResult.scanId);
  assert.equal(stored.source, 'LIVE');

  await assert.rejects(
    () => submitScanResult({ apiUrl: baseUrl, token: 'wrong-token-that-is-still-long-enough-000', result: { ...result, scanId: randomUUID() } }),
    /UNAUTHORIZED_SCANNER/,
  );
});
