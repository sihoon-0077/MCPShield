import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify, parseEnv } from 'node:util';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { controlConfig } from '../../apps/api/src/control-config.js';

test('local configuration generates distinct credentials and never overwrites evidence keys', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mcpshield-config-test-'));
  const output = join(dir, '.env.local');
  const script = fileURLToPath(new URL('../../scripts/ops/init-control.mjs', import.meta.url));
  try {
    const run = await promisify(execFile)(process.execPath, [script, '--output', output], { windowsHide: true });
    const original = await readFile(output, 'utf8');
    const env = parseEnv(original);
    const config = controlConfig(env);
    assert.equal(config?.credentials.length, 3);
    assert.equal(new Set(config?.credentials.map((credential) => credential.token)).size, 3);
    assert.equal(config?.chainDecision, undefined);
    for (const secret of [env.ADMIN_API_TOKEN, env.SCANNER_API_TOKEN, env.CONTROL_EVIDENCE_KEY, ...config!.credentials.map((credential) => credential.token)]) {
      assert.doesNotMatch(run.stdout + run.stderr, new RegExp(secret));
    }
    await assert.rejects(promisify(execFile)(process.execPath, [script, '--output', output], { windowsHide: true }));
    assert.equal(await readFile(output, 'utf8'), original);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
