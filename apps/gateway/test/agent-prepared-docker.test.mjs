import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { tsImport } from 'tsx/esm/api';
import { exactReleaseIdentity } from '../../../packages/contracts-sdk/src/v2-identity.mjs';
import { prepareNpmClosure } from '../../../services/resolver/src/npm-closure.mjs';
import { artifactDigest } from '../../../services/scanner/src/scanner.mjs';
import { canonicalJson } from '../../../services/scanner/src/evidence.mjs';
import { observePreparedRuntime } from '../../../services/scanner/src/prepared-runtime.mjs';
import { createPreparedReleaseBinding } from '../../../services/scanner/src/prepared-binding.mjs';
import { removeFixtureSnapshot } from '../../../services/scanner/src/snapshot.mjs';
import { runGatewayAgent } from '../../../benchmarks/gateway-agent.mjs';

// Actual prepared image/SDK/Gateway; local fake model and admission issuer. No provider-quality/quorum claim.
test('scoped authored mailbox → prepared image → fake model decision → real signed Gateway call and revoke', {
  skip: process.env.MCPSHIELD_DOCKER_TESTS !== '1' || !process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE,
  timeout: 300000,
}, async () => {
  assert.equal(process.platform, 'linux');
  const { scopedTools, scopedMailbox } = await tsImport('../../../tests/api/scoped-fixture.ts', import.meta.url);
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-prepared-agent-')), sourceDir = join(workspace, 'source');
  let prepared, server;
  try {
    await mkdir(sourceDir);
    const pkg = { name: 'synthetic-scoped-agent', version: '1.0.0', bin: 'server.js' };
    await writeFile(join(sourceDir, 'package.json'), JSON.stringify(pkg));
    await writeFile(join(sourceDir, 'package-lock.json'), JSON.stringify({ name: pkg.name, version: pkg.version, lockfileVersion: 3, packages: { '': { name: pkg.name, version: pkg.version } } }));
    await writeFile(join(sourceDir, 'server.js'), scopedMailbox(false));
    const digest = await artifactDigest(sourceDir);
    prepared = await prepareNpmClosure({ root: sourceDir, sourceDigest: digest, sourceTreeDigest: digest,
      builderImageDigest: process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE, platform: { os: 'linux', architecture: 'amd64' } });
    assert.deepEqual(prepared.issues, []);
    const observed = await observePreparedRuntime({ descriptor: prepared.descriptor, expectedDescriptorDigest: prepared.descriptorDigest,
      probePlan: { scenarios: ['NORMAL', 'ADVERSARIAL'].map((kind, i) => ({ scenarioId: `mail-${i}`, kind,
        goal: 'Read authored synthetic mailbox.', toolName: 'list_messages', argumentsJson: JSON.stringify({ limit: i + 1 }) })) } });
    assert.deepEqual(observed.report.issues, []);
    const binding = createPreparedReleaseBinding({ sourceReleaseId: `0x${'1'.repeat(64)}`, descriptor: observed.observedDescriptor,
      executionPolicy: JSON.parse(observed.bundle.files['runtime/execution-policy.json']) });
    const identity = { schemaVersion: 'mcpshield.gateway-prepared.v1', ...exactReleaseIdentity({ toolId: `npm:${pkg.name}`, ...binding }), binding, tools: scopedTools };
    const identityFile = join(workspace, 'identity.json');
    await writeFile(identityFile, JSON.stringify(identity), { mode: 0o600 });
    const keys = generateKeyPairSync('ed25519');
    const env = { MCPSHIELD_POLICY_HASH: `0x${'a'.repeat(64)}`, MCPSHIELD_CONTROL_RELEASE_ID: identity.releaseId,
      MCPSHIELD_TENANT_ID: 'synthetic-agent', MCPSHIELD_CACHE_PUBLIC_KEY: keys.publicKey.export({ type: 'spki', format: 'pem' }),
      MCPSHIELD_CACHE_KEY_ID: 'synthetic-agent-issuer', MCPSHIELD_CHAIN_ID: '31337', MCPSHIELD_REGISTRY_CONTRACT: `0x${'b'.repeat(40)}`,
      MCPSHIELD_VALIDATOR_SET_VERSION: '1', MCPSHIELD_CONTROL_TOKEN: 'SYNTHETIC_ADMISSION_TOKEN' };
    let revoked = false, modelRequests = 0;
    server = createServer(async (request, response) => {
      const chunks = []; for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks));
      response.setHeader('content-type', 'application/json');
      if (request.url === '/model') {
        modelRequests++;
        assert.equal(request.headers.authorization, undefined, 'Gateway token must not reach model endpoint');
        assert.deepEqual(JSON.parse(body.prompt).tools, scopedTools);
        return response.end(JSON.stringify({ disposition: 'SELECTED', calls: [{ name: 'list_messages', argumentsJson: '{"limit":1}' }] }));
      }
      assert.equal(request.url, '/v1/admission/check');
      assert.equal(request.headers.authorization, `Bearer ${env.MCPSHIELD_CONTROL_TOKEN}`);
      assert.equal(body.releaseId, identity.releaseId);
      assert.equal(body.artifactDigest, binding.artifactDigest);
      assert.equal(body.toolSurfaceHash, binding.toolSurfaceHash);
      assert.equal(body.operationClass, 'WRITE_EXTERNAL', 'missing annotations must not be promoted to read-only approval');
      const now = Date.now(), snapshot = { schemaVersion: '1.0.0', keyId: env.MCPSHIELD_CACHE_KEY_ID, releaseId: body.releaseId,
        artifactDigest: body.artifactDigest, toolSurfaceHash: body.toolSurfaceHash, policyHash: env.MCPSHIELD_POLICY_HASH,
        tenantId: env.MCPSHIELD_TENANT_ID, operationClass: body.operationClass, chainId: 31337,
        registryContract: env.MCPSHIELD_REGISTRY_CONTRACT, validatorSetVersion: 1, observedBlock: 123, blockHash: `0x${'c'.repeat(64)}`,
        issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 30000).toISOString(), decision: revoked ? 'BLOCK' : 'ALLOW',
        status: revoked ? 'REVOKED' : 'VERIFIED', reasonCode: revoked ? 'RELEASE_REVOKED' : 'RELEASE_VERIFIED', reportUrl: `/v1/releases/${body.releaseId}` };
      response.end(JSON.stringify({ snapshot, signature: sign(null, Buffer.from(canonicalJson(snapshot)), keys.privateKey).toString('base64url') }));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const url = `http://127.0.0.1:${server.address().port}`;
    const options = { preparedIdentityPath: identityFile, apiUrl: url, controlEnvironment: env, allowRemoteAi: true,
      timeoutMs: 60000, ai: { provider: 'custom', url: `${url}/model`, timeoutMs: 5000 } };
    const allowed = await runGatewayAgent(options);
    assert.equal(allowed.status, 'COMPLETED', JSON.stringify(allowed));
    assert.deepEqual(allowed.subjects, ['Welcome']);
    assert.equal(allowed.admissions.findLast(record => record.phase === 'CALL').controlReleaseId, identity.releaseId);
    assert.equal(allowed.model.provider, 'custom');
    assert.equal(allowed.modelEvidenceMode, 'LOCAL_CONTRACT_TEST');
    assert.equal(allowed.asrMeasured, false);
    revoked = true;
    const blocked = await runGatewayAgent(options);
    assert.equal(blocked.status, 'GATEWAY_BLOCKED', JSON.stringify(blocked));
    assert.equal(blocked.reasonCode, 'RELEASE_REVOKED');
    assert.equal(blocked.modelAttempted, false);
    assert.equal(modelRequests, 1);
  } finally {
    await new Promise(resolve => server ? server.close(resolve) : resolve());
    await prepared?.cleanup?.();
    await removeFixtureSnapshot(workspace);
  }
});
