import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import ganache from "ganache";
import { Contract, JsonRpcProvider, NonceManager, Wallet, id } from "ethers";
import { deployV2 } from "../../contracts/scripts/deploy-v2.js";
import { defaultPolicy } from "../../apps/api/src/control-policy.js";
import { hash } from "../../apps/api/src/control-plane.js";
import { quarantineReason, runValidatorV3, verdictFromReport } from "../../apps/validator/src/v3.js";
import { bytes32, createReleaseRegistryV3, exactReleaseIdentity, ROUND_OUTCOMES } from "../../packages/contracts-sdk/src/v3.js";
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
  assert.equal(quarantineReason({ findings: [f("CANARY_EXFILTRATION", "CRITICAL", "SANDBOX")] }), "CANARY_EXFILTRATION");
  assert.equal(quarantineReason({ findings: [f("CANARY_EXFILTRATION", "CRITICAL", "AI")] }), null);
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
