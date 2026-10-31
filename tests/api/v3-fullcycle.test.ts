import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as pause } from "node:timers/promises";
import ganache from "ganache";
import { Wallet, id } from "ethers";
import { compileReleaseRegistry } from "../../contracts/scripts/compile.js";
import { deployV2 } from "../../contracts/scripts/deploy-v2.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { buildApp } from "../../apps/api/src/app.js";
import { controlConfig } from "../../apps/api/src/control-config.js";
import { runControlWorkerOnce } from "../../apps/api/src/control-worker.js";
import { V2Relayer, runChainActionOnce } from "../../apps/api/src/chain-outbox.js";
import { v2ChainReader } from "../../apps/api/src/registry-v2-client.js";
import { indexV2 } from "../../apps/indexer/src/v2-indexer.js";
import { runValidatorV3 } from "../../apps/validator/src/v3.js";
import { defaultPolicy, hash, type ControlOptions } from "../../apps/api/src/control-plane.js";
import { attestationV2Types } from "../../packages/contracts-sdk/src/v2.js";
import { attestationV3Types, evidenceDocument, quarantineV3Types } from "../../packages/contracts-sdk/src/v3.js";
// @ts-expect-error Shared scanner/Gateway are ESM JavaScript.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared scanner/Gateway are ESM JavaScript.
import { artifactDigest, loadManifest, toolSurfaceHash } from "../../services/scanner/src/scanner.mjs";
// @ts-expect-error Shared scanner/Gateway are ESM JavaScript.
import { getAdmission } from "../../apps/gateway/src/index.mjs";

const repo = resolve(import.meta.dirname, "../..");
const SAFE = join(repo, "demo/fixtures/mail-mcp-1.0.0"), MALICIOUS = join(repo, "demo/fixtures/mail-mcp-1.0.1");

test("control config selects ReleaseRegistryV3 by address and refuses an ambiguous registry", () => {
  const env = { CONTROL_PLANE_ENABLED: "true", CONTROL_PLANE_CREDENTIALS: JSON.stringify([{ token: "synthetic-v3-config-token", tenantId: "t", role: "admin" }]),
    CONTROL_EVIDENCE_KEY: "a".repeat(64), CONTROL_V2_RPC_URLS: "http://127.0.0.1:9", CONTROL_V2_CHAIN_ID: "1337", CONTROL_V2_RELAYER_KEY: `0x${"1".repeat(64)}` };
  const address = `0x${"2".repeat(40)}`, options = controlConfig({ ...env, CONTROL_V3_REGISTRY_ADDRESS: address })!;
  try {
    assert.equal(options.v2Relayer?.registryVersion, 3);
    assert.equal(options.v2Relayer?.domain.version, "3");
    assert.equal(options.v2Relayer?.registryAddress, address);
  } finally { options.v2Relayer?.close(); (options.chainDecision as any)?.close?.(); }
  assert.throws(() => controlConfig({ ...env, CONTROL_V2_REGISTRY_ADDRESS: address, CONTROL_V3_REGISTRY_ADDRESS: address }), /REGISTRY_VERSION_AMBIGUOUS/);
});

test("V3 operator relay: validators vote from their own scans and evidence, dissent is kept, 2-of-3 approves and revokes, both Gateways follow", { timeout: 240000 }, async () => {
  // Compile before the in-process chain starts: a multi-second solc stall during chain traffic times out RPC requests.
  for (const name of ["ValidatorRegistry", "PolicyRegistry", "ReleaseRegistryV3"]) compileReleaseRegistry(name);
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 5 } });
  const dir = await mkdtemp(join(tmpdir(), "mcpshield-v3-relay-"));
  const owned: { app?: Awaited<ReturnType<typeof buildApp>>; relayer?: V2Relayer; reader?: ReturnType<typeof v2ChainReader>; store?: ControlStore } = {};
  let pumping = false, pump: Promise<void> | undefined;
  try {
    await chain.listen(0, "127.0.0.1");
    const rpc = `http://127.0.0.1:${chain.address().port}`;
    const keys = (Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[]).map((account) => account.secretKey);
    const [keyA, keyB, keyC] = keys.slice(1, 4), [A, B, C] = [keyA, keyB, keyC].map((key) => new Wallet(key).address);
    const deployment = await deployV2(rpc, keys[0], [A, B, C], 1337, undefined, "ReleaseRegistryV3");
    const registryAddress = deployment.releaseRegistry.address, policyHash = hash(defaultPolicy);
    const relayer = owned.relayer = new V2Relayer(rpc, registryAddress, 1337, keys[0], 3);
    const store = owned.store = await ControlStore.open(join(dir, "control.sqlite"));
    const key = generateKeyPairSync("ed25519"), token = "synthetic-v3-test-admin-token";
    const options: ControlOptions = { store, credentials: [{ token, tenantId: "test-team", role: "admin" }],
      artifactPath: join(dir, "artifacts"), evidencePath: join(dir, "evidence"), evidenceKey: "9".repeat(64),
      signingKey: key.privateKey.export({ format: "pem", type: "pkcs8" }).toString(), signingKeyId: "v3-integration",
      v2Relayer: relayer, chainDecision: owned.reader = v2ChainReader({ rpcUrls: [rpc], registryContract: registryAddress, chainId: 1337, confirmations: 1 }) };
    // Operator report fixture, as in the V2 full cycle. The validators below run the real scanner on their own copies.
    options.scanArtifact = async ({ artifactDir }) => {
      const manifest = await loadManifest(artifactDir), malicious = manifest.version === "1.0.1";
      const findings = malicious ? [{ code: "CANARY_EXFILTRATION", deterministic: true, severity: "CRITICAL", stage: "SANDBOX", evidence: {}, message: "Synthetic report fixture" }] : [];
      const result = { scanStatus: malicious ? "FAILED" : "PASSED", artifactDigest: await artifactDigest(artifactDir), toolSurfaceHash: toolSurfaceHash(manifest.tools), findings };
      return { result, bundle: createEvidenceBundle({ "report.json": { ...result, scope: "STATIC_AI_SANDBOX" },
        "sandbox/events.json": { mode: "DOCKER", complete: true }, "sandbox/mcp.json": { complete: true }, "static/findings.json": [], "semantic/model-output.json": { findings: [] } }) };
    };
    const app = owned.app = await buildApp({ adminApiToken: "unused-legacy-admin", scannerApiToken: "unused-legacy-scan", controlPlane: options });
    await app.listen({ host: "127.0.0.1", port: 0 });
    const apiUrl = `http://127.0.0.1:${(app.server.address() as any).port}`, auth = { authorization: `Bearer ${token}` };
    const call = (method: "GET" | "POST", url: string, payload?: any) => app.inject({ method, url, headers: auth, payload });
    const post = async (url: string, payload: any = {}, headers = {}) => {
      const response = await app.inject({ method: "POST", url, headers: { ...auth, ...headers }, payload });
      assert.ok(response.statusCode < 300, `${url}: ${response.body}`); return response.json();
    };
    const refused = async (url: string, payload: any, code: string) => {
      const response = await call("POST", url, payload);
      assert.equal(response.statusCode, 400, response.body); assert.equal(response.json().error.code, code);
    };
    const mine = () => chain.provider.request({ method: "evm_mine", params: [] });
    const settle = async (actionId: string) => {
      for (let attempt = 0; attempt < 40; attempt++) {
        await mine(); await runChainActionOnce(store, relayer);
        const action = (await call("GET", `/v1/chain/actions/${actionId}`)).json().action;
        if (action.status === "COMPLETED") return action;
        assert.notEqual(action.status, "FAILED", JSON.stringify(action)); await pause(100);
      }
      assert.fail("chain action did not settle");
    };
    const pumpChain = async <T>(work: () => Promise<T>) => {
      pumping = true;
      pump = (async () => { while (pumping) { await mine(); await runChainActionOnce(store, relayer); await pause(100); } })();
      try { return await work(); } finally { pumping = false; await pump; }
    };
    const prepare = async (version: string) => {
      const release = (await post("/v1/releases/resolve", { sourceType: "fixture", locator: `mail-mcp-${version}` })).release;
      await settle((await post(`/v1/releases/${release.releaseId}/register`)).action.actionId);
      const scan = (await post("/v1/scans", { releaseId: release.releaseId, policyHash }, { "idempotency-key": version })).scan;
      await runControlWorkerOnce(store, options);
      assert.equal((await store.scan("test-team", scan.scanId))?.status, "COMPLETED");
      await mine(); // the round starts at the scan's completion; validators refuse a window that starts after the chain head
      return { release, scan };
    };
    const validate = (privateKey: string, scanId: string, artifactDir: string, extra: Partial<Parameters<typeof runValidatorV3>[0]> = {}) => runValidatorV3({ privateKey,
      rpcUrl: rpc, chainId: 1337, registryAddress, policyHash, artifactDir, evidenceDir: join(dir, "validator-evidence"), relay: { apiUrl, token, scanId }, ...extra });
    const votes = async (releaseId: string) => {
      const response = await call("GET", `/v1/releases/${releaseId}/votes`); assert.equal(response.statusCode, 200, response.body); return response.json();
    };
    const byValidator = (round: any) => Object.fromEntries(round.votes.map((vote: any) => [vote.validator, vote]));
    const gateway = (release: any, agent: string) => getAdmission({ identity: { releaseId: release.legacyReleaseId, artifactDigest: release.artifactDigest,
      toolSurfaceHash: release.toolSurfaceHash }, mode: "live", apiBaseUrl: apiUrl, timeoutMs: 3000, policyHash, controlReleaseId: release.releaseId, tenantId: "test-team",
      publicKey: key.publicKey.export({ type: "spki", format: "pem" }).toString(), keyId: "v3-integration", chainId: 1337, registryContract: registryAddress,
      validatorSetVersion: 1, apiToken: token, operationClass: "READ_PRIVATE", admissionMode: "strict", agentId: agent });

    await settle((await post(`/v1/policies/${policyHash}/publish`)).action.actionId);
    const safe = await prepare("1.0.0");
    // The operator announces a round but no verdict and no evidence: those belong to each validator.
    const announced = (await call("GET", `/v1/scans/${safe.scan.scanId}/attestation?validator=${C}`)).json();
    assert.equal(announced.registryVersion, 3); assert.deepEqual(announced.types, attestationV3Types); assert.equal(announced.domain.version, "3");
    assert.equal(announced.operatorVerdict, "PASS"); assert.equal(announced.payload.verdict, undefined); assert.equal(announced.payload.evidenceHash, undefined);
    // A V2-shaped vote that signs the operator's report is not a V3 vote.
    const v2Shaped = { ...announced.payload, reportRoot: `0x${"3".repeat(64)}`, verdict: 0 };
    await refused("/v1/validator/attestations", { scanId: safe.scan.scanId, payload: v2Shaped,
      signature: await new Wallet(keyC).signTypedData(announced.domain, attestationV2Types, v2Shaped) }, "INVALID_ATTESTATION");
    assert.equal((await gateway(safe.release, "Gateway-A")).decision, "BLOCK", "no votes yet");

    const [safeA, safeB] = await pumpChain(async () => [await validate(keyA, safe.scan.scanId, SAFE), await validate(keyB, safe.scan.scanId, SAFE)]);
    assert.deepEqual([safeA.verdict, safeB.verdict], ["PASS", "PASS"]);
    assert.notEqual(safeA.evidenceHash, safeB.evidenceHash, "each validator signs its own evidence file");
    assert.ok([safeA, safeB].every((run) => run.transactions.length === 1 && run.transactions[0].relayed === true && /^0x[0-9a-f]{64}$/.test(run.transactions[0].txHash)));

    // C dissents after the 2-of-3 decision: ABSTAIN on an AI suspicion in its own evidence. The relay records it like any vote.
    const cTemplate = (await call("GET", `/v1/scans/${safe.scan.scanId}/attestation?validator=${C}`)).json();
    const identity = { releaseId: cTemplate.payload.releaseId, artifactDigest: cTemplate.payload.artifactDigest, manifestDigest: cTemplate.payload.manifestDigest,
      toolSurfaceDigest: cTemplate.payload.toolSurfaceDigest };
    const dissent = evidenceDocument(C, identity, { scanStatus: "PASSED", findings: [{ code: "SEMANTIC_BEHAVIOR_MISMATCH", severity: "HIGH", stage: "AI", deterministic: false }] },
      { verdict: "ABSTAIN", basis: ["SEMANTIC_BEHAVIOR_MISMATCH"] });
    const sign = (payload: any) => new Wallet(keyC).signTypedData(cTemplate.domain, attestationV3Types, payload);
    const abstain = { ...cTemplate.payload, evidenceHash: dissent.evidenceHash, verdict: 2 };
    await refused("/v1/validator/attestations", { scanId: safe.scan.scanId, payload: abstain, signature: await sign(abstain), evidence: `${dissent.file} ` }, "VALIDATOR_EVIDENCE_HASH_MISMATCH");
    const moved = { ...abstain, validUntil: abstain.validUntil - 1 };
    await refused("/v1/validator/attestations", { scanId: safe.scan.scanId, payload: moved, signature: await sign(moved) }, "ATTESTATION_BINDING_MISMATCH");
    await settle((await post("/v1/validator/attestations", { scanId: safe.scan.scanId, payload: abstain, signature: await sign(abstain), evidence: dissent.file })).action.actionId);

    await mine();
    for (const agent of ["Gateway-A", "Gateway-B"]) assert.equal((await gateway(safe.release, agent)).decision, "ALLOW", agent);
    const safeView = await votes(safe.release.releaseId);
    assert.equal(safeView.status, "VERIFIED"); assert.equal(safeView.needsReview, false);
    const safeRound = safeView.rounds[0], safeVotes = byValidator(safeRound);
    assert.equal(safeRound.outcome, "APPROVED"); assert.deepEqual([safeRound.approvals, safeRound.rejections, safeRound.abstentions], [2, 0, 1]);
    assert.equal(safeView.decisionRound, safeRound.roundId);
    assert.equal(safeVotes[A].verdict, "PASS"); assert.equal(safeVotes[A].agreesWithOperator, true); assert.equal(safeVotes[A].evidence.consistent, true);
    assert.equal(safeVotes[C].verdict, "ABSTAIN"); assert.equal(safeVotes[C].agreesWithOperator, false);
    assert.deepEqual(safeVotes[C].evidence.basis, ["SEMANTIC_BEHAVIOR_MISMATCH"]); assert.equal(safeVotes[C].evidence.consistent, true);
    const served = await call("GET", `/v1/releases/${safe.release.releaseId}/votes/${safeRound.roundId}/${C}/evidence`);
    assert.equal(`0x${createHash("sha256").update(served.body).digest("hex")}`, dissent.evidenceHash, "the exact evidence bytes are served for re-hashing");

    // 1.0.1: C's own sandbox sees the canary leak and quarantines directly; two FAIL votes revoke; B's late FAIL stays on record.
    const bad = await prepare("1.0.1");
    const quarantineTemplate = (await call("GET", `/v1/scans/${bad.scan.scanId}/quarantine?validator=${A}`)).json();
    const unproven = { ...quarantineTemplate.payload, evidenceHash: `0x${"4".repeat(64)}`, reasonCode: id("CANARY_EXFILTRATION") };
    await refused("/v1/validator/quarantines", { scanId: bad.scan.scanId, payload: unproven,
      signature: await new Wallet(keyA).signTypedData(quarantineTemplate.domain, quarantineV3Types, unproven) }, "VALIDATOR_EVIDENCE_INVALID");
    const [badC, badA, badB] = await pumpChain(async () => [await validate(keyC, bad.scan.scanId, MALICIOUS, { baselineDir: SAFE, quarantine: true }),
      await validate(keyA, bad.scan.scanId, MALICIOUS, { baselineDir: SAFE }), await validate(keyB, bad.scan.scanId, MALICIOUS, { baselineDir: SAFE })]);
    assert.deepEqual(badC.transactions.map((tx: any) => tx.kind), ["QUARANTINE", "ATTEST"]);
    assert.deepEqual([badC.verdict, badA.verdict, badB.verdict], ["FAIL", "FAIL", "FAIL"]);
    await mine();
    for (const agent of ["Gateway-A", "Gateway-B"]) {
      const denied = await gateway(bad.release, agent);
      assert.equal(denied.decision, "BLOCK"); assert.equal(denied.releaseStatus, "REVOKED");
    }

    await indexV2(store, relayer, { deploymentBlock: deployment.releaseRegistry.blockNumber, confirmations: 1 });
    const badView = await votes(bad.release.releaseId), badRound = badView.rounds.find((round: any) => round.outcome === "REJECTED"), badVotes = byValidator(badRound);
    assert.equal(badView.status, "REVOKED"); assert.equal(badView.decisionRound, badRound.roundId);
    assert.deepEqual(badView.quarantines.map((item: any) => [item.validator, item.reason, item.txHash]), [[C, "CANARY_EXFILTRATION", badC.transactions[0].txHash]],
      "the direct quarantine is shown with its validator, reason and transaction");
    assert.deepEqual([badRound.rejections, badRound.approvals, badRound.abstentions], [3, 0, 0]);
    assert.equal(badVotes[A].afterDecision, false); assert.equal(badVotes[B].afterDecision, true, "a vote after the revocation is kept, not dropped");
    assert.ok(badRound.votes.every((vote: any) => /^0x[0-9a-f]{64}$/.test(vote.txHash) && vote.evidence?.consistent === true && vote.agreesWithOperator === true));
    assert.equal(byValidator((await votes(safe.release.releaseId)).rounds[0])[C].afterDecision, true);
    const indexed = await store.get("test-team", "release", bad.release.releaseId);
    assert.equal(indexed?.status, "REVOKED"); assert.equal(indexed?.chain.registryVersion, 3); assert.equal(indexed?.reportRoot, badRound.roundId);
    const history = (await store.events("test-team", bad.release.releaseId)).map((event) => event.eventName);
    for (const name of ["chain.ReleaseQuarantined", "chain.VoteRecorded", "chain.RoundDecided", "chain.ReleaseRevoked"]) assert.ok(history.includes(name), name);
  } finally {
    pumping = false; await pump;
    const cleanup = await Promise.allSettled([Promise.resolve().then(() => owned.app?.close())]);
    if (!owned.app || cleanup[0].status === "rejected") await Promise.allSettled([() => owned.relayer?.close(), () => owned.reader?.close(), () => owned.store?.close()].map((close) => Promise.resolve().then(close)));
    await Promise.allSettled([chain.close(), rm(dir, { recursive: true, force: true })]);
  }
});
