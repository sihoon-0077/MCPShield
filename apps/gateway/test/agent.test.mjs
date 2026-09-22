import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runGatewayAgent } from '../../../benchmarks/gateway-agent.mjs';
import { createGatewayClient } from '../../../scripts/demo/mcp-client.mjs';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const replay = resolve(root, 'scripts/demo/replay.json');
const safe = resolve(root, 'demo/fixtures/mail-mcp-1.0.0');
const revoked = resolve(root, 'demo/fixtures/mail-mcp-1.0.1');
const selected = { disposition: 'SELECTED', calls: [{ name: 'list_messages', argumentsJson: '{}' }] };

test('fake provider → actual SDK → unchanged Gateway: selection, refusal, invalid output and revocation', async t => {
  const temp = await mkdtemp(join(tmpdir(), 'mcpshield-agent-contract-'));
  let decision = selected;
  let requests = 0;
  let onDecision = async () => {};
  const server = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    const input = JSON.parse(body);
    assert.deepEqual(input.tools, []);
    assert.equal(JSON.parse(input.prompt).tools[0].name, 'list_messages');
    requests += 1;
    await onDecision();
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(decision));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const options = { localContractTest: true, artifactDir: safe, replayFile: replay,
    ai: { provider: 'custom', url: `http://127.0.0.1:${server.address().port}`, timeoutMs: 1000 } };
  try {
    await t.test('selected call receives synthetic mail and joins Gateway-owned identity/decision trace', async () => {
      const result = await runGatewayAgent(options);
      assert.equal(result.evidenceKind, 'LOCAL_PROVIDER_CONTRACT_TEST');
      assert.equal(result.asrMeasured, false);
      assert.equal(result.status, 'COMPLETED');
      assert.equal(result.taskCompleted, true);
      assert.deepEqual(result.subjects, ['Welcome']);
      assert.equal(result.model.provider, 'custom');
      assert.equal(result.toolRequests[0].outcome, 'RESULT_RECEIVED');
      const admission = result.admissions.find(record => record.phase === 'CALL');
      assert.equal(admission.releaseId, 'mail-mcp@1.0.0');
      assert.equal(admission.toolName, 'list_messages');
      assert.equal(admission.reasonCode, 'RELEASE_VERIFIED');
      assert.match(admission.artifactDigest, /^sha256:[a-f0-9]{64}$/);
      assert.equal(admission.source, 'REPLAY');
      assert.equal('spawnAttempted' in result, false, 'diagnostic logs alone are not candidate-spawn proof');
    });
    await t.test('model refusal is not attributed to Gateway enforcement', async () => {
      decision = { disposition: 'REFUSED', calls: [] };
      const result = await runGatewayAgent(options);
      assert.equal(result.status, 'MODEL_NO_CALL');
      assert.equal(result.taskCompleted, false);
      assert.deepEqual(result.toolRequests, []);
      assert.equal(result.admissions.some(record => record.phase === 'CALL'), false);
    });
    await t.test('out-of-profile model output is never forwarded', async () => {
      decision = { disposition: 'SELECTED', calls: [{ name: 'run_shell', argumentsJson: '{}' }] };
      const result = await runGatewayAgent(options);
      assert.equal(result.status, 'MODEL_INVALID');
      assert.deepEqual(result.toolRequests, []);
    });
    await t.test('revoked candidate is denied before any model selection', async () => {
      const before = requests;
      const result = await runGatewayAgent({ ...options, artifactDir: revoked });
      assert.equal(result.status, 'GATEWAY_BLOCKED');
      assert.equal(result.reasonCode, 'RELEASE_REVOKED');
      assert.equal(result.modelAttempted, false);
      assert.equal(requests, before);
      assert.deepEqual(result.toolRequests, []);
      assert.equal(result.admissions[0].status, 'REVOKED');
    });
    await t.test('revocation after tool discovery rejects the model-selected subsequent call', async () => {
      const mutableReplay = join(temp, 'replay.json');
      const evidence = JSON.parse(await readFile(replay, 'utf8'));
      await writeFile(mutableReplay, JSON.stringify(evidence));
      decision = selected;
      onDecision = async () => {
        Object.assign(evidence.decisions['mail-mcp@1.0.0'], { decision: 'BLOCK', releaseStatus: 'REVOKED', reasonCode: 'RELEASE_REVOKED' });
        await writeFile(mutableReplay, JSON.stringify(evidence));
      };
      const result = await runGatewayAgent({ ...options, replayFile: mutableReplay });
      assert.equal(result.status, 'GATEWAY_BLOCKED');
      assert.equal(result.reasonCode, 'RELEASE_REVOKED');
      assert.equal(result.modelAttempted, true);
      assert.equal(result.taskCompleted, false);
      assert.equal(result.toolRequests[0].outcome, 'REQUEST_FAILED');
      assert.equal(result.admissions.findLast(record => record.phase === 'CALL').decision, 'BLOCK');
      onDecision = async () => {};
    });
    await t.test('provider failure is recorded as model error, not successful defense', async () => {
      const result = await runGatewayAgent({ ...options, ai: { ...options.ai, url: 'http://127.0.0.1:1' } });
      assert.equal(result.status, 'MODEL_ERROR');
      assert.equal(result.errorCode, 'AI_TRANSPORT_FAILED');
      assert.equal(result.taskCompleted, false);
      assert.deepEqual(result.toolRequests, []);
    });
  } finally {
    await new Promise(resolve => server.close(resolve));
    await rm(temp, { recursive: true, force: true });
  }
});

test('Agent cannot silently fall back to host execution, remote contract provider or injected environment', async () => {
  await assert.rejects(runGatewayAgent({ artifactDir: safe, allowRemoteAi: true }), /prepared signed admission/);
  await assert.rejects(runGatewayAgent({ localContractTest: true, artifactDir: safe, replayFile: replay,
    ai: { url: 'https://provider.example' } }), /loopback fake provider/);
  assert.throws(() => createGatewayClient({ root, artifactDir: safe, mode: 'live',
    controlEnvironment: { NODE_OPTIONS: '--require anything' } }), /unsupported Gateway control environment/);
  assert.throws(() => createGatewayClient({ root, artifactDir: safe, preparedIdentityPath: 'identity.json' }), /exactly one/);
});
