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
  const ignore = await readFile(new URL('../../.dockerignore', import.meta.url), 'utf8');
  for (const entry of ['data', '.env.*', '**/*.sqlite', '**/*.pem', '**/*.key']) {
    assert.ok(ignore.split(/\r?\n/).includes(entry), `private build exclusion: ${entry}`);
  }
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
    for (const secret of [env.ADMIN_API_TOKEN, env.SCANNER_API_TOKEN, env.CONTROL_EVIDENCE_KEY, env.MCPSHIELD_GRAFANA_ADMIN_PASSWORD, ...config!.credentials.map((credential) => credential.token)]) {
      assert.ok(secret && secret.length >= 32);
      assert.ok(!(run.stdout + run.stderr).includes(secret));
    }
    await assert.rejects(promisify(execFile)(process.execPath, [script, '--output', output], { windowsHide: true }));
    assert.equal(await readFile(output, 'utf8'), original);
    const observabilityOutput = join(dir, '.env.observability.local');
    const observability = await promisify(execFile)(process.execPath, [script, '--observability', '--output', observabilityOutput], { windowsHide: true });
    const passwordConfig = parseEnv(await readFile(observabilityOutput, 'utf8'));
    assert.deepEqual(Object.keys(passwordConfig), ['MCPSHIELD_GRAFANA_ADMIN_PASSWORD']);
    assert.match(passwordConfig.MCPSHIELD_GRAFANA_ADMIN_PASSWORD, /^[a-f0-9]{64}$/);
    assert.ok(!observability.stdout.includes(passwordConfig.MCPSHIELD_GRAFANA_ADMIN_PASSWORD));
    await assert.rejects(promisify(execFile)(process.execPath, [script, '--observability', '--output', observabilityOutput], { windowsHide: true }));
  } finally { await rm(dir, { recursive: true, force: true }); }
});
