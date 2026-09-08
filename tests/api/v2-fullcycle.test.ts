import assert from "node:assert/strict";
import { test } from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { setTimeout as pause } from "node:timers/promises";
import ganache from "ganache";
import { Wallet } from "ethers";
import { deployV2 } from "../../contracts/scripts/deploy-v2.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { buildApp } from "../../apps/api/src/app.js";
import { runControlWorkerOnce } from "../../apps/api/src/control-worker.js";
import { V2Relayer, enqueueChainAction, runChainActionOnce, reconcileV2Actions } from "../../apps/api/src/chain-outbox.js";
import { v2ChainReader } from "../../apps/api/src/registry-v2-client.js";
import { indexV2 } from "../../apps/indexer/src/v2-indexer.js";
import { runValidatorFanout } from "../../apps/validator/src/v2.js";
import { defaultPolicy, hash, type ControlOptions } from "../../apps/api/src/control-plane.js";
// @ts-expect-error Shared scanner/Gateway are ESM JavaScript.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared scanner/Gateway are ESM JavaScript.
import { artifactDigest, loadManifest, toolSurfaceHash } from "../../services/scanner/src/scanner.mjs";
// @ts-expect-error Shared scanner/Gateway are ESM JavaScript.
import { AdmissionBlockedError, getAdmission, runArtifact } from "../../apps/gateway/src/index.mjs";

async function fullCycle(realDocker: boolean) {
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 5 } });
  await chain.listen(0, "127.0.0.1");
  const rpc = `http://127.0.0.1:${chain.address().port}`;
  const accounts = Object.values(chain.provider.getInitialAccounts()) as {secretKey: string}[];
  const validators = accounts.slice(1, 4).map((a) => new Wallet(a.secretKey));
  const deployment = await deployV2(rpc, accounts[0].secretKey, validators.map((v) => v.address), 1337);
  const relayer = new V2Relayer(rpc, deployment.releaseRegistry.address, 1337, accounts[0].secretKey);
  const dir = await mkdtemp(join(tmpdir(), "mcpshield-v2-test-"));
  const store = await ControlStore.open(join(dir, "control.sqlite"));
  const key = generateKeyPairSync("ed25519"), token = "synthetic-v2-test-admin-token";
  const options: ControlOptions = { store, credentials: [{ token, tenantId: "test-team", role: "admin" }],
    artifactPath: join(dir, "artifacts"), evidencePath: join(dir, "evidence"), evidenceKey: "9".repeat(64),
    signingKey: key.privateKey.export({ format: "pem", type: "pkcs8" }).toString(), signingKeyId: "v2-integration",
    v2Relayer: relayer, chainDecision: v2ChainReader({ rpcUrls: [rpc], registryContract: deployment.releaseRegistry.address, chainId: 1337, confirmations: 1 }) };
  if (!realDocker) options.scanArtifact = async ({ artifactDir }) => {
    // Explicit report test double: the regular test proves trust-plane/outbox logic; the opt-in case executes Docker.
    const manifest = await loadManifest(artifactDir), malicious = manifest.version === "1.0.1";
    const findings = malicious ? [{ code: "CANARY_EXFILTRATION", deterministic: true, severity: "CRITICAL", stage: "SANDBOX", evidence: {}, message: "Synthetic report fixture" }] : [];
    const result = { scanStatus: malicious ? "FAILED" : "PASSED", artifactDigest: await artifactDigest(artifactDir), toolSurfaceHash: toolSurfaceHash(manifest.tools), findings };
    return { result, bundle: createEvidenceBundle({ "report.json": { ...result, scope: "STATIC_AI_SANDBOX" },
      "sandbox/events.json": { mode: "DOCKER", complete: true }, "sandbox/mcp.json": { complete: true }, "static/findings.json": [], "semantic/model-output.json": { findings: [] } }) };
  };
  const originalMode = process.env.CONTROL_SANDBOX_MODE;
  if (realDocker) process.env.CONTROL_SANDBOX_MODE = "docker";
  const app = await buildApp({ adminApiToken: "unused-legacy-admin", scannerApiToken: "unused-legacy-scan", controlPlane: options });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const apiUrl = `http://127.0.0.1:${(app.server.address() as any).port}`, auth = { authorization: `Bearer ${token}` };
  const post = async (url: string, payload: any = {}, headers = {}) => {
    const response = await app.inject({ method: "POST", url, headers: { ...auth, ...headers }, payload });
    assert.ok(response.statusCode < 300, `${url}: ${response.body}`); return response.json();
  };
  const settle = async (actionId: string) => {
    for (let attempt = 0; attempt < 40; attempt++) {
      await chain.provider.request({ method: "evm_mine", params: [] });
      await runChainActionOnce(store, relayer);
      const action = (await app.inject({ url: `/v1/chain/actions/${actionId}`, headers: auth })).json().action;
      if (action.status === "COMPLETED") return action;
      assert.notEqual(action.status, "FAILED", JSON.stringify(action));
      await pause(100);
    }
    assert.fail("chain action did not settle");
  };
  const vote = async (scanId: string, validator: Wallet, quarantine = false) => {
    const template = (await app.inject({ url: `/v1/scans/${scanId}/${quarantine ? "quarantine" : "attestation"}?validator=${validator.address}`, headers: auth })).json();
    assert.ok(template.payload, JSON.stringify(template));
    const signature = await validator.signTypedData(template.domain, template.types, template.payload);
    const response = await post(`/v1/validator/${quarantine ? "quarantines" : "attestations"}`, { scanId, payload: template.payload, signature },
      { traceparent: `00-${"f".repeat(32)}-${"e".repeat(16)}-01`, baggage: "authorization=synthetic-trace-poison" });
    await settle(response.action.actionId);
    assert.equal((await post(`/v1/validator/${quarantine ? "quarantines" : "attestations"}`, { scanId, payload: template.payload, signature })).action.actionId, response.action.actionId);
    return { template, signature };
  };
  try {
    await settle((await post(`/v1/policies/${hash(defaultPolicy)}/publish`)).action.actionId);
    const prepareRelease = async (version: string) => {
      const release = (await post("/v1/releases/resolve", { sourceType: "fixture", locator: `mail-mcp-${version}` })).release;
      await settle((await post(`/v1/releases/${release.releaseId}/register`)).action.actionId);
      const scan = (await post("/v1/scans", { releaseId: release.releaseId, policyHash: hash(defaultPolicy) }, { "idempotency-key": version })).scan;
      await runControlWorkerOnce(store, options);
      const completed = await store.scan("test-team", scan.scanId);
      assert.equal(completed?.status, "COMPLETED", JSON.stringify(completed?.lastError));
      assert.equal(completed?.result?.verdict, version === "1.0.0" ? "PASS" : "FAIL");
      return { release, scan };
    };
    const safe = await prepareRelease("1.0.0");
    const beforeVotes = await post("/v1/admission/check", { releaseId: safe.release.releaseId, artifactDigest: safe.release.artifactDigest,
      toolSurfaceHash: safe.release.toolSurfaceHash, policyHash: hash(defaultPolicy), mode: "strict", operationClass: "READ_PRIVATE" });
    assert.equal(beforeVotes.decision, "BLOCK");
    let pumping = true;
    const pump = (async () => { while (pumping) { await chain.provider.request({ method: "evm_mine", params: [] }); await runChainActionOnce(store, relayer); await pause(100); } })();
    try {
      const fanout = await runValidatorFanout({ apiUrl, token, scanId: safe.scan.scanId, privateKeys: accounts.slice(1, 3).map((account) => account.secretKey),
        chainId: 1337, registryAddress: deployment.releaseRegistry.address, policyHash: hash(defaultPolicy), rpcUrl: rpc });
      assert.equal(fanout.operations.length, 2); assert.equal(fanout.mode, "SINGLE_INSTITUTION_DEMO");
    } finally { pumping = false; await pump; }
    const gatewayOptions = (release: any, agent: string) => ({ identity: { releaseId: release.legacyReleaseId,
      artifactDigest: release.artifactDigest, toolSurfaceHash: release.toolSurfaceHash }, mode: "live", apiBaseUrl: apiUrl,
      timeoutMs: 3000, policyHash: hash(defaultPolicy), controlReleaseId: release.releaseId, tenantId: "test-team",
      publicKey: key.publicKey.export({ type: "spki", format: "pem" }).toString(), keyId: "v2-integration", chainId: 1337,
      registryContract: deployment.releaseRegistry.address, validatorSetVersion: 1, apiToken: token, operationClass: "READ_PRIVATE", admissionMode: "strict", agentId: agent });
    const gateway = (release: any, agent: string) => getAdmission(gatewayOptions(release, agent));
    assert.equal((await gateway(safe.release, "Gateway-A")).decision, "ALLOW");
    const client = new Client({ name: "v2-fullcycle", version: "1" }), transport = new StdioClientTransport({ command: process.execPath,
      args: [fileURLToPath(new URL("../../apps/gateway/src/index.mjs", import.meta.url)), "stdio"], stderr: "pipe",
      env: { ...getDefaultEnvironment(), MCPSHIELD_ARTIFACT_DIR: (await store.get("test-team", "release", safe.release.releaseId))!.artifactDir,
        MCPSHIELD_MODE: "live", MCPSHIELD_API_URL: apiUrl, MCPSHIELD_POLICY_HASH: hash(defaultPolicy), MCPSHIELD_CONTROL_RELEASE_ID: safe.release.releaseId,
        MCPSHIELD_TENANT_ID: "test-team", MCPSHIELD_CONTROL_TOKEN: token, MCPSHIELD_CACHE_PUBLIC_KEY: key.publicKey.export({ type: "spki", format: "pem" }).toString(),
        MCPSHIELD_CACHE_KEY_ID: "v2-integration", MCPSHIELD_CHAIN_ID: "1337", MCPSHIELD_REGISTRY_CONTRACT: deployment.releaseRegistry.address,
        MCPSHIELD_VALIDATOR_SET_VERSION: "1", MCPSHIELD_ADMISSION_MODE: "strict" } });
    transport.stderr?.on("data", () => {});
    try {
      await client.connect(transport);
      assert.equal((await client.listTools()).tools[0].name, "list_messages");
      const result = await client.callTool({ name: "list_messages", arguments: {} });
      assert.notEqual(result.isError, true);
      assert.equal(JSON.parse((result.content as any[])[0].text).messages[0].subject, "Welcome");
    } finally { await client.close(); }
    await indexV2(store, relayer, { deploymentBlock: deployment.releaseRegistry.blockNumber, confirmations: 1 });
    const scanTrace = (await store.scan("test-team", safe.scan.scanId))!.traceId;
    const tracedActions = await store.query("SELECT trace_parent,submission_trace_parent,tx_hash FROM cp_chain_actions WHERE release_id = ? AND kind = 'ATTEST'", [safe.release.releaseId]);
    assert.equal(tracedActions.length, 2);
    for (const action of tracedActions) {
      assert.equal(action.trace_parent.split("-")[1], scanTrace);
      assert.equal(action.submission_trace_parent.split("-")[1], scanTrace);
      assert.notEqual(action.trace_parent, action.submission_trace_parent);
    }
    const indexedVotes = (await store.events("test-team", safe.release.releaseId)).filter((event) => event.eventName.startsWith("chain.") && tracedActions.some((action) => action.tx_hash === event.payload.txHash));
    assert.ok(indexedVotes.length >= 2); assert.ok(indexedVotes.every((event) => event.traceId === scanTrace));
    const snapshot = await chain.provider.request({ method: "evm_snapshot", params: [] });
    const bad = await prepareRelease("1.0.1");
    await vote(bad.scan.scanId, validators[0], true);
    assert.equal((await gateway(bad.release, "Gateway-A")).releaseStatus, "QUARANTINED");
    await vote(bad.scan.scanId, validators[0]); await vote(bad.scan.scanId, validators[1]);
    const badScanTrace = (await store.scan("test-team", bad.scan.scanId))!.traceId;
    for (const action of await store.query("SELECT trace_parent,submission_trace_parent FROM cp_chain_actions WHERE release_id = ? AND kind IN ('ATTEST','QUARANTINE')", [bad.release.releaseId])) {
      assert.equal(action.trace_parent.split("-")[1], badScanTrace);
      assert.equal(action.submission_trace_parent.split("-")[1], badScanTrace);
      assert.doesNotMatch(JSON.stringify(action), /synthetic-trace-poison|authorization/);
    }
    for (const agent of ["Gateway-A", "Gateway-B"]) {
      const denied = await gateway(bad.release, agent); assert.equal(denied.decision, "BLOCK"); assert.equal(denied.releaseStatus, "REVOKED");
      await assert.rejects(runArtifact({ ...gatewayOptions(bad.release, agent), artifactDir: (await store.get("test-team", "release", bad.release.releaseId))!.artifactDir, capture: true }), (error: any) => error instanceof AdmissionBlockedError && error.decision.releaseStatus === "REVOKED");
    }
    await indexV2(store, relayer, { deploymentBlock: deployment.releaseRegistry.blockNumber, confirmations: 1 });
    assert.equal((await store.get("test-team", "release", bad.release.releaseId))?.status, "REVOKED");
    assert.equal(await reconcileV2Actions(store, relayer), 0);
    const actions = await store.query("SELECT raw_tx,tx_hash,nonce FROM cp_chain_actions WHERE state = 'COMPLETED'");
    assert.ok(actions.every((action) => action.raw_tx && action.tx_hash && Number.isInteger(action.nonce)));
    assert.equal(new Set(actions.map((action) => action.nonce)).size, actions.length);
    // Crash after broadcast before receipt persistence: replay identical bytes, never a second transaction.
    const [last] = await store.query("SELECT * FROM cp_chain_actions WHERE state = 'COMPLETED' ORDER BY nonce DESC LIMIT 1");
    await store.query("UPDATE cp_chain_actions SET state = 'PREPARED' WHERE action_id = ?", [last.action_id]);
    const parallel = await Promise.all([runChainActionOnce(store, relayer), runChainActionOnce(store, relayer)]);
    assert.equal(parallel.filter(Boolean).length, 1);
    const [recovered] = await store.query("SELECT * FROM cp_chain_actions WHERE action_id = ?", [last.action_id]);
    assert.equal(recovered.state, "COMPLETED"); assert.equal(recovered.raw_tx, last.raw_tx); assert.equal(recovered.tx_hash, last.tx_hash);
    const secondDeployment = await deployV2(rpc, accounts[0].secretKey, validators.map((v) => v.address), 1337);
    const otherRegistry = new V2Relayer(rpc, secondDeployment.releaseRegistry.address, 1337, accounts[0].secretKey);
    try {
      const [registration] = await store.query("SELECT * FROM cp_chain_actions WHERE kind = 'REGISTER_RELEASE' AND release_id = ?", [safe.release.releaseId]);
      const anotherAction = await enqueueChainAction(store, otherRegistry, "test-team", "REGISTER_RELEASE", JSON.parse(registration.payload));
      assert.notEqual(anotherAction.actionId, registration.action_id);
      assert.equal(anotherAction.registryAddress, secondDeployment.releaseRegistry.address.toLowerCase());
      assert.equal(await runChainActionOnce(store, relayer), false, "old registry must not claim a new registry action");
      await runChainActionOnce(store, otherRegistry);
      assert.equal((await otherRegistry.registry.releases(safe.release.releaseId)).exists, true);
      await pause(300); await runChainActionOnce(store, otherRegistry);
      const [scoped] = await store.query("SELECT state FROM cp_chain_actions WHERE action_id = ?", [anotherAction.actionId]);
      assert.equal(scoped.state, "COMPLETED");
    } finally { otherRegistry.close(); }
    await chain.provider.request({ method: "evm_revert", params: [snapshot] });
    await pause(300); // ethers' bounded request cache must expire before observing the changed canonical head.
    assert.ok(await reconcileV2Actions(store, relayer) > 0);
    await indexV2(store, relayer, { deploymentBlock: deployment.releaseRegistry.blockNumber, confirmations: 1 });
    assert.equal((await store.get("test-team", "release", bad.release.releaseId))?.status, "UNVERIFIED");
    assert.ok((await store.events("test-team", bad.release.releaseId)).some((event) => event.eventName === "chain.event.orphaned"));
  } finally {
    if (originalMode === undefined) delete process.env.CONTROL_SANDBOX_MODE; else process.env.CONTROL_SANDBOX_MODE = originalMode;
    await app.close(); await chain.close(); await rm(dir, { recursive: true, force: true });
  }
}
test("V2 genuine EVM outbox/quorum/quarantine and two signed Gateway decisions (report fixture)", { timeout: 120000 }, () => fullCycle(false));
test("V2 real Docker scan to EVM quorum and two-Gateway blocking", { timeout: 180000, skip: process.env.MCPSHIELD_DOCKER_TESTS !== "1" }, () => fullCycle(true));
