import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import ganache from "ganache";
import { Contract, JsonRpcProvider, NonceManager, Wallet, id } from "ethers";
import { deployV2 } from "../../contracts/scripts/deploy-v2.js";
import { defaultPolicy } from "../../apps/api/src/control-policy.js";
import { hash } from "../../apps/api/src/control-plane.js";
import { quarantineReason, runValidatorV3, verdictFromReport } from "../../apps/validator/src/v3.js";
import { bytes32, checkedVoteEvidence, createReleaseRegistryV3, exactReleaseIdentity, ROUND_OUTCOMES } from "../../packages/contracts-sdk/src/v3.js";
// @ts-expect-error Resolver is shared ESM JavaScript.
import { resolveArtifact } from "../../services/resolver/src/resolver.mjs";

const repo = resolve(import.meta.dirname, "../..");
const SAFE = join(repo, "demo/fixtures/mail-mcp-1.0.0"), MALICIOUS = join(repo, "demo/fixtures/mail-mcp-1.0.1");
const STATUS = ["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"];

test("verdict rule: deterministic non-AI HIGH is FAIL, AI-only or medium findings ABSTAIN (AI is a witness)", () => {
  const f = (code: string, severity: string, stage: string, deterministic = true) => ({ code, severity, stage, deterministic });
  assert.equal(verdictFromReport({ scanStatus: "PASSED", findings: [] }).verdict, "PASS");
  assert.deepEqual(verdictFromReport({ scanStatus: "FAILED", findings: [f("UNDECLARED_EGRESS", "HIGH", "SANDBOX"), f("SEMANTIC_BEHAVIOR_MISMATCH", "HIGH", "AI")] }),
    { verdict: "FAIL", basis: ["UNDECLARED_EGRESS"] });
  assert.equal(verdictFromReport({ scanStatus: "FAILED", findings: [f("SEMANTIC_BEHAVIOR_MISMATCH", "HIGH", "AI")] }).verdict, "ABSTAIN");
  assert.equal(verdictFromReport({ scanStatus: "FAILED", findings: [f("TOOL_SURFACE_CHANGED", "MEDIUM", "STATIC")] }).verdict, "ABSTAIN");
  assert.equal(verdictFromReport({ scanStatus: "FAILED", findings: [f("UNDECLARED_EGRESS", "HIGH", "STATIC", false)] }).verdict, "ABSTAIN", "non-deterministic never fails alone");
  assert.equal(verdictFromReport({}).verdict, "ABSTAIN", "a malformed report is not a PASS");
  assert.equal(verdictFromReport({ scanStatus: "INCONCLUSIVE", findings: [] }).verdict, "ABSTAIN", "an incomplete sandbox is not a PASS");
  assert.deepEqual(verdictFromReport({ scanStatus: "PASSED", findings: [f("SEMANTIC_BEHAVIOR_MISMATCH", "HIGH", "AI", false)] }),
    { verdict: "ABSTAIN", basis: ["SEMANTIC_BEHAVIOR_MISMATCH"] }, "an AI suspicion on a passed scan holds the release");
  assert.equal(verdictFromReport({ scanStatus: "PASSED", findings: [f("SEMANTIC_BEHAVIOR_MISMATCH", "MEDIUM", "STATIC", false)] }).verdict, "PASS", "a medium metadata signal is recorded, not blocking");
  assert.equal(quarantineReason({ findings: [f("CANARY_EXFILTRATION", "CRITICAL", "SANDBOX")] }), "CANARY_EXFILTRATION");
  assert.equal(quarantineReason({ findings: [f("CANARY_EXFILTRATION", "CRITICAL", "AI")] }), null);
  // A configured AI witness that did not answer holds a clean scan; it never softens a deterministic FAIL.
  const witness = (status: "COMPLETED" | "UNAVAILABLE") => ({ required: true as const, provider: "openai", model: "witness-model", status });
  assert.deepEqual(verdictFromReport({ scanStatus: "PASSED", findings: [] }, witness("UNAVAILABLE")), { verdict: "ABSTAIN", basis: ["AI_UNAVAILABLE"] });
  assert.equal(verdictFromReport({ scanStatus: "PASSED", findings: [] }, witness("COMPLETED")).verdict, "PASS");
  assert.deepEqual(verdictFromReport({ scanStatus: "FAILED", findings: [f("UNDECLARED_EGRESS", "HIGH", "SANDBOX")] }, witness("UNAVAILABLE")),
    { verdict: "FAIL", basis: ["UNDECLARED_EGRESS"] });
});

test("V3 validator AI witness: an unanswered witness holds a clean release, an answer lets it pass, a deterministic FAIL stands", { timeout: 120000 }, async () => {
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 4 } });
  const evidenceDir = await mkdtemp(join(tmpdir(), "mcpshield-validator-v3-ai-"));
  let mode: "fail" | "answer" = "fail";
  const calls: string[] = [];
  const witnessServer = createServer(async (request, response) => {
    const chunks: Buffer[] = []; for await (const chunk of request) chunks.push(chunk as Buffer);
    calls.push(JSON.parse(Buffer.concat(chunks).toString()).model);
    if (mode === "fail") return void response.writeHead(500).end("unavailable");
    const answer = { riskClaims: [], semanticDiff: { purposeChanged: false, dataScopeExpanded: false, newHiddenObligation: false }, needsHumanReview: false };
    response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ status: "completed", model: "witness-model",
      output: [{ type: "message", content: [{ type: "output_text", text: JSON.stringify(answer) }] }], usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } }));
  });
  let provider: JsonRpcProvider | undefined;
  try {
    await chain.listen(0, "127.0.0.1");
    await new Promise<void>((done) => witnessServer.listen(0, "127.0.0.1", done));
    const rpc = `http://127.0.0.1:${chain.address().port}`;
    const keys = (Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[]).map((a) => a.secretKey);
    const deployment = await deployV2(rpc, keys[0], keys.slice(1, 4).map((k) => new Wallet(k).address), 1337, undefined, "ReleaseRegistryV3");
    provider = new JsonRpcProvider(rpc, 1337, { staticNetwork: true, cacheTimeout: -1 });
    const owner = new NonceManager(new Wallet(keys[0], provider));
    const registry: any = createReleaseRegistryV3(deployment.releaseRegistry.address, owner);
    const policyHash = hash(defaultPolicy);
    await (await new Contract(deployment.policyRegistry.address, ["function publish(bytes32,bytes32)"], owner).publish(policyHash, policyHash)).wait();
    const register = async (dir: string) => {
      const resolved = await resolveArtifact({ sourceType: "local", locator: dir }), exact = exactReleaseIdentity(resolved);
      await (await registry.registerRelease(exact.toolId, bytes32(resolved.artifactDigest), bytes32(resolved.manifestDigest), bytes32(resolved.toolSurfaceHash))).wait();
      return exact.releaseId;
    };
    const [safe, bad] = [await register(SAFE), await register(MALICIOUS)];
    const t = Number((await provider.getBlock("latest"))!.timestamp);
    const scan = { allowRemoteAi: true, aiProvider: "openai", aiModel: "witness-model", aiToken: "witness-token",
      aiUrl: `http://127.0.0.1:${(witnessServer.address() as any).port}/v1/responses`, aiTimeoutMs: 10000 };
    const run = (releaseId: string, artifactDir: string, baselineDir?: string) => runValidatorV3({ rpcUrl: rpc, chainId: 1337, registryAddress: deployment.releaseRegistry.address,
      policyHash, evidenceDir, privateKey: keys[1], releaseId, artifactDir, baselineDir, validFrom: t - 5, validUntil: t - 5 + 3600, scan, dryRun: true });
    const evidence = async (result: any) => {
      const file = (await readFile(result.evidenceFile)).toString();
      const doc = JSON.parse(file);
      return { doc, check: checkedVoteEvidence(file, { evidenceHash: result.evidenceHash, validator: result.validator, release: doc.release }) };
    };

    const held = await run(safe, SAFE);
    assert.deepEqual([held.verdict, held.basis, held.ai], ["ABSTAIN", ["AI_UNAVAILABLE"], { model: "witness-model", status: "UNAVAILABLE" }]);
    const heldEvidence = await evidence(held);
    assert.equal(heldEvidence.doc.ai.status, "UNAVAILABLE", "the evidence file says the witness did not answer");
    assert.equal(heldEvidence.check.consistent, true, "auditors derive the same hold from the file");

    const failed = await run(bad, MALICIOUS, SAFE);
    assert.equal(failed.verdict, "FAIL", "deterministic evidence stands even when the witness is silent");
    assert.ok(failed.basis.includes("CANARY_EXFILTRATION"));

    mode = "answer";
    const passed = await run(safe, SAFE);
    assert.deepEqual([passed.verdict, passed.ai], ["PASS", { model: "witness-model", status: "COMPLETED" }]);
    assert.equal((await evidence(passed)).check.consistent, true);
    assert.ok(calls.length >= 3 && calls.every((model) => model === "witness-model"), "every scan asked the configured model");

    // Remote AI allowed but no endpoint the scanner would call: the scanner quietly uses its local analysis, so this must hold too.
    const asked = calls.length;
    const unwired = await runValidatorV3({ rpcUrl: rpc, chainId: 1337, registryAddress: deployment.releaseRegistry.address, policyHash, evidenceDir, privateKey: keys[1],
      releaseId: safe, artifactDir: SAFE, validFrom: t - 5, validUntil: t - 5 + 3600, dryRun: true,
      scan: { allowRemoteAi: true, aiProvider: "custom", aiModel: "witness-model", aiToken: "witness-token" } });
    assert.deepEqual([unwired.verdict, unwired.basis, unwired.ai], ["ABSTAIN", ["AI_UNAVAILABLE"], { model: "witness-model", status: "UNAVAILABLE" }]);
    const unwiredEvidence = await evidence(unwired);
    assert.equal(unwiredEvidence.doc.ai.error, "AI_NOT_CONFIGURED");
    assert.equal(unwiredEvidence.check.consistent, true);
    assert.equal(calls.length, asked, "no model was asked");
  } finally {
    provider?.destroy();
    witnessServer.close();
    await chain.close();
    await rm(evidenceDir, { recursive: true, force: true });
  }
});

test("V3 validator CLI refuses AI settings the AI transport would refuse, before any scan or chain call", { timeout: 120000 }, async () => {
  const evidenceDir = await mkdtemp(join(tmpdir(), "mcpshield-validator-v3-cli-"));
  // Nothing listens on these values: a run that got past the AI check would fail on the chain, not with VALIDATOR_AI_CONFIG_INVALID.
  const env = { ...process.env, VALIDATOR_PRIVATE_KEY: `0x${"11".repeat(32)}`, CONTROL_V2_RPC_URLS: "http://127.0.0.1:9", CONTROL_V2_CHAIN_ID: "1337",
    CONTROL_V3_REGISTRY_ADDRESS: `0x${"22".repeat(20)}`, CONTROL_VALIDATOR_POLICY_HASH: `0x${"33".repeat(32)}`, VALIDATOR_ARTIFACT_DIR: SAFE, VALIDATOR_EVIDENCE_DIR: evidenceDir,
    VALIDATOR_RELEASE_ID: `0x${"44".repeat(32)}`, VALIDATOR_VALID_FROM: "1", VALIDATOR_VALID_UNTIL: "2", VALIDATOR_ALLOW_REMOTE_AI: "true",
    VALIDATOR_AI_MODEL: "witness-model", VALIDATOR_AI_TOKEN: "witness-token", VALIDATOR_AI_TOKEN_FILE: "", VALIDATOR_AI_URL: "", VALIDATOR_AI_TIMEOUT_MS: "120000", CONTROL_SCAN_ID: "" };
  try {
    for (const refused of [
      { VALIDATOR_AI_PROVIDER: "custom" },
      { VALIDATOR_AI_PROVIDER: "openai", VALIDATOR_AI_TIMEOUT_MS: "180000" },
      { VALIDATOR_AI_PROVIDER: "custom", VALIDATOR_AI_URL: "http://192.0.2.10/v1/responses" },
      { VALIDATOR_AI_PROVIDER: "custom", VALIDATOR_AI_URL: "https://user:secret@example.com/v1/responses" },
      { VALIDATOR_AI_PROVIDER: "openai", VALIDATOR_AI_URL: "https://example.com/v1/responses" },
      { VALIDATOR_AI_PROVIDER: "openai", VALIDATOR_AI_MODEL: "two words" },
    ]) {
      const result = spawnSync(process.execPath, ["--import", "tsx", join(repo, "apps/validator/src/v3.ts")], { cwd: repo, env: { ...env, ...refused }, encoding: "utf8", timeout: 60000 });
      assert.equal(result.status, 1, JSON.stringify(refused));
      assert.match(result.stderr, /VALIDATOR_AI_CONFIG_INVALID/, JSON.stringify(refused));
    }
    // Control: a loopback custom endpoint passes the AI check and the run fails later, on the unreachable chain.
    const accepted = spawnSync(process.execPath, ["--import", "tsx", join(repo, "apps/validator/src/v3.ts")], { cwd: repo, encoding: "utf8", timeout: 60000,
      env: { ...env, VALIDATOR_AI_PROVIDER: "custom", VALIDATOR_AI_URL: "http://127.0.0.1:9/v1/responses" } });
    assert.equal(accepted.status, 1);
    assert.doesNotMatch(accepted.stderr, /VALIDATOR_AI_CONFIG_INVALID/);
  } finally { await rm(evidenceDir, { recursive: true, force: true }); }
});

test("V3 validators: own scans, own evidence, 2-of-3 approve and revoke, direct quarantine, wrong bytes refused", { timeout: 120000 }, async () => {
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 5 } });
  const evidenceDir = await mkdtemp(join(tmpdir(), "mcpshield-validator-v3-"));
  let provider: JsonRpcProvider | undefined;
  try {
    await chain.listen(0, "127.0.0.1");
    const rpc = `http://127.0.0.1:${chain.address().port}`;
    const keys = (Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[]).map((a) => a.secretKey);
    const validatorKeys = keys.slice(1, 4);
    const deployment = await deployV2(rpc, keys[0], validatorKeys.map((k) => new Wallet(k).address), 1337, undefined, "ReleaseRegistryV3");
    provider = new JsonRpcProvider(rpc, 1337, { staticNetwork: true, cacheTimeout: -1 });
    const owner = new NonceManager(new Wallet(keys[0], provider));
    const registry: any = createReleaseRegistryV3(deployment.releaseRegistry.address, owner);
    const policyHash = hash(defaultPolicy);
    await (await new Contract(deployment.policyRegistry.address, ["function publish(bytes32,bytes32)"], owner).publish(policyHash, policyHash)).wait();
    const register = async (dir: string) => {
      const resolved = await resolveArtifact({ sourceType: "local", locator: dir }), exact = exactReleaseIdentity(resolved);
      await (await registry.registerRelease(exact.toolId, bytes32(resolved.artifactDigest), bytes32(resolved.manifestDigest), bytes32(resolved.toolSurfaceHash))).wait();
      return exact.releaseId;
    };
    const [safe, bad] = [await register(SAFE), await register(MALICIOUS)];
    const head = async () => Number((await provider!.getBlock("latest"))!.timestamp);
    const window = async () => { const t = await head(); return { validFrom: t - 5, validUntil: t - 5 + 3600 }; };
    const base = { rpcUrl: rpc, chainId: 1337, registryAddress: deployment.releaseRegistry.address, policyHash, evidenceDir, relayerKey: keys[0] };
    const status = async (releaseId: string) => STATUS[Number((await registry.getDecision(releaseId, policyHash)).status)];

    const sw = await window();
    const approvals = [];
    for (const key of validatorKeys.slice(0, 2)) approvals.push(await runValidatorV3({ ...base, ...sw, privateKey: key, releaseId: safe, artifactDir: SAFE }));
    assert.deepEqual(approvals.map((r) => r.verdict), ["PASS", "PASS"]);
    assert.equal(await status(safe), "VERIFIED");
    assert.notEqual(approvals[0].evidenceHash, approvals[1].evidenceHash, "each validator signs its own evidence");
    for (const r of approvals) {
      const bytes = await readFile(r.evidenceFile);
      assert.equal(`0x${createHash("sha256").update(bytes).digest("hex")}`, r.evidenceHash, "the signed hash is the hash of the file on disk");
      const doc = JSON.parse(bytes.toString());
      assert.deepEqual([doc.validator, doc.release.releaseId, doc.verdict], [r.validator, safe, "PASS"]);
      const vote = await registry.getVote(r.roundId, r.validator);
      assert.deepEqual([vote.cast, vote.evidenceHash], [true, r.evidenceHash]);
    }
    const again = await runValidatorV3({ ...base, ...sw, privateKey: validatorKeys[0], releaseId: safe, artifactDir: SAFE });
    assert.equal(again.skipped, "ALREADY_VOTED");

    // Wrong bytes: a validator holding 1.0.0 cannot vote on the 1.0.1 release.
    await assert.rejects(runValidatorV3({ ...base, ...(await window()), privateKey: validatorKeys[2], releaseId: bad, artifactDir: SAFE }), /ARTIFACT_IDENTITY_MISMATCH/);

    // 1.0.1: validator C quarantines from its own key, then A and B FAIL on their own scans.
    const bw = await window();
    const c = await runValidatorV3({ ...base, ...bw, privateKey: validatorKeys[2], releaseId: bad, artifactDir: MALICIOUS, baselineDir: SAFE, quarantine: true, relayerKey: undefined });
    assert.deepEqual([c.verdict, c.transactions.map((t: any) => t.kind)], ["FAIL", ["QUARANTINE", "ATTEST"]]);
    assert.ok(c.basis.includes("CANARY_EXFILTRATION"));
    const quarantineTx = await provider.getTransaction(c.transactions[0].txHash);
    assert.equal(quarantineTx!.from, new Wallet(validatorKeys[2]).address, "the quarantine is sent by the validator itself");
    assert.equal(await status(bad), "QUARANTINED");
    await runValidatorV3({ ...base, ...bw, privateKey: validatorKeys[0], releaseId: bad, artifactDir: MALICIOUS, baselineDir: SAFE });
    assert.equal(await status(bad), "REVOKED");
    const round = await registry.getRound(c.roundId);
    assert.deepEqual([ROUND_OUTCOMES[Number(round.outcome)], Number(round.rejections)], ["REJECTED", 2]);
    assert.equal(await status(safe), "VERIFIED", "revoking 1.0.1 leaves 1.0.0 alone");
    await assert.rejects(runValidatorV3({ ...base, validFrom: (await head()) + 60, validUntil: (await head()) + 120, privateKey: validatorKeys[1], releaseId: safe, artifactDir: SAFE }),
      /ROUND_WINDOW_INVALID/);
  } finally {
    provider?.destroy();
    await chain.close();
    await rm(evidenceDir, { recursive: true, force: true });
  }
});
