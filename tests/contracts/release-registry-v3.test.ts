// ReleaseRegistryV3 (ADR-008). Each "[X] fixed" test replays the scenario of the same letter in
// release-registry-v2-known-gaps.test.ts and asserts the V3 behaviour. "[X] kept" tests pin a V2 behaviour
// that ADR-008 keeps on purpose. Determinism follows the known-gaps suite: fixed genesis time and
// miner.timestampIncrement = 1, so every mined block is the previous block + 1 s.
import assert from "node:assert/strict";
import { test } from "node:test";
import ganache from "ganache";
import { BrowserProvider, ContractFactory, Wallet, id } from "ethers";
import { compileReleaseRegistry } from "../../contracts/scripts/compile.js";
import { attestationV2Domain, attestationV2Types, createReleaseRegistryV2 } from "../../packages/contracts-sdk/src/v2.js";
import { attestationV3Domain, attestationV3Types, exactReleaseIdentity, quarantineV3Types, releaseRegistryV3Abi, ROUND_OUTCOMES } from "../../packages/contracts-sdk/src/v3.js";

const DAY = 86_400;
const GENESIS = new Date("2026-01-01T00:00:00Z");
const STATUS = ["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"];
const PASS = 0, FAIL = 1, ABSTAIN = 2;
const dig = `0x${"a".repeat(64)}`, surface = `0x${"b".repeat(64)}`;
const P1 = id("policy-v1"), P2 = id("policy-v2");
const CANARY = id("CANARY_EXFILTRATION");
// Every validator signs evidence of its own scan; no two hashes in a round are equal.
const evidence = (validator: number, label: string) => id(`evidence:${validator}:${label}`);
const policyLabel = new Map([[P1, "P1"], [P2, "P2"]]);
const reasonLabel = new Map(["FRESH_SCAN", "PASS_QUORUM", "FAIL_QUORUM", "SPLIT_VOTE", "STALE_APPROVAL", "EXPIRY", "QUARANTINE_ENDED", "CANARY_EXFILTRATION"]
  .map((label) => [id(label), label]));
const compiled = Object.fromEntries(["ValidatorRegistry", "PolicyRegistry", "ReleaseRegistryV3"].map((name) => [name, compileReleaseRegistry(name)]));

type Vote = { policy?: string; label: string; verdict: number; validFrom: number; validUntil: number; evidenceHash?: string };

async function revertOf(action: () => Promise<unknown>): Promise<string> {
  try { await action(); } catch (error: any) {
    return error?.info?.error?.data?.reason ?? error?.reason ?? `UNDECODED: ${error?.shortMessage ?? error?.message}`;
  }
  return "NO_REVERT";
}

async function fixture() {
  const chain: any = ganache.provider({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 5 },
    chain: { time: GENESIS }, miner: { timestampIncrement: 1 } });
  const provider = new BrowserProvider(chain, 1337, { cacheTimeout: -1, staticNetwork: true });
  const owner = await provider.getSigner(0);
  const keys = (Object.values(chain.getInitialAccounts()) as { secretKey: string }[]).map((a) => new Wallet(a.secretKey, provider));
  const deploy = async (name: string, args: any[]) => {
    const instance: any = await new ContractFactory(compiled[name].abi, compiled[name].bytecode, owner).deploy(...args);
    await instance.waitForDeployment(); return instance;
  };
  const validators = await deploy("ValidatorRegistry", [owner.address, keys.slice(1, 4).map((k) => k.address)]);
  const policies = await deploy("PolicyRegistry", [owner.address]);
  for (const policy of [P1, P2]) await (await policies.publish(policy, policy)).wait();
  const registry = await deploy("ReleaseRegistryV3", [owner.address, await validators.getAddress(), await policies.getAddress()]);
  const domain = attestationV3Domain(1337, await registry.getAddress());
  const now = async () => Number(BigInt((await chain.request({ method: "eth_getBlockByNumber", params: ["latest", false] })).timestamp));
  const advanceTo = async (timestamp: number) => { await chain.request({ method: "evm_mine", params: [timestamp] }); };
  const advance = async (seconds: number) => advanceTo((await now()) + seconds);
  // Each tool gets its own artifact bytes unless a test shares them on purpose ([F]); revocation binds bytes.
  const artifacts = new Map<string, string>();
  const register = async (toolId: string, artifact = id(`artifact:${toolId}`)) => {
    const identity = exactReleaseIdentity({ toolId, artifactDigest: artifact, manifestDigest: dig, toolSurfaceHash: surface });
    await (await registry.registerRelease(identity.toolId, artifact, dig, surface)).wait();
    artifacts.set(identity.releaseId, artifact);
    return identity.releaseId;
  };
  const payloadOf = async (signer: number, releaseId: string, vote: Vote) => ({ releaseId, artifactDigest: artifacts.get(releaseId)!, manifestDigest: dig,
    toolSurfaceDigest: surface, policyHash: vote.policy ?? P1, evidenceHash: vote.evidenceHash ?? evidence(signer, vote.label), verdict: vote.verdict,
    validFrom: vote.validFrom, validUntil: vote.validUntil, validatorSetVersion: Number(await validators.version()),
    nonce: Number(await registry.nonces(keys[signer].address)), deadline: (await now()) + 3600 });
  // Relayed by the owner, signed off-chain by keys[signer].
  const attest = async (signer: number, releaseId: string, vote: Vote) => {
    const payload = await payloadOf(signer, releaseId, vote);
    await (await registry.submitAttestation(payload, await keys[signer].signTypedData(domain, attestationV3Types, payload))).wait();
  };
  const quarantine = async (index: number, releaseId: string, label: string, ttl: number, policy = P1) => {
    const validator: any = registry.connect(await provider.getSigner(index));
    await (await validator.quarantine(releaseId, policy, id(`quarantine:${label}`), CANARY, (await now()) + ttl)).wait();
  };
  const decision = async (releaseId: string, policy = P1) => {
    const d = await registry.getDecision(releaseId, policy);
    return { status: STATUS[Number(d.status)], roundId: d.reportRoot as string, approvals: Number(d.approvals), rejections: Number(d.rejections) };
  };
  const status = async (releaseId: string, policy = P1) => (await decision(releaseId, policy)).status;
  const roundOf = (releaseId: string, vote: Pick<Vote, "policy" | "validFrom" | "validUntil"> & Partial<Vote>) => registry.roundIdOf(releaseId, vote.policy ?? P1, vote.validFrom, vote.validUntil, 1) as Promise<string>;
  const round = async (roundId: string) => {
    const r = await registry.getRound(roundId);
    return { outcome: ROUND_OUTCOMES[Number(r.outcome)], approvals: Number(r.approvals), rejections: Number(r.rejections), abstentions: Number(r.abstentions) };
  };
  const events = async (name: string) => (await registry.queryFilter(registry.filters[name](), 0, "latest")).map((log: any) => log.args);
  const statusEvents = async () => (await events("ReleaseStatusChanged")).map((e: any) =>
    `${policyLabel.get(e.policyHash) ?? e.policyHash}:${STATUS[Number(e.previousStatus)]}->${STATUS[Number(e.newStatus)]}:${reasonLabel.get(e.reasonCode) ?? e.reasonCode}`);
  return { chain, provider, keys, validators, policies, registry, domain, now, advance, advanceTo, register, payloadOf, attest, quarantine,
    decision, status, roundOf, round, events, statusEvents, close: () => chain.disconnect() };
}

test("independent evidence: two PASS votes on different evidence hashes verify; a later FAIL is kept as dissent", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now(), scan = { label: "scan-1", validFrom: t, validUntil: t + DAY };
    for (const v of [1, 2]) await f.attest(v, r, { ...scan, verdict: PASS });
    const roundId = await f.roundOf(r, scan);
    assert.deepEqual(await f.decision(r), { status: "VERIFIED", roundId, approvals: 2, rejections: 0 });
    await f.attest(3, r, { ...scan, verdict: FAIL });
    assert.equal(await f.status(r), "VERIFIED", "one FAIL after a 2-of-3 PASS does not overturn it");
    assert.deepEqual(await f.round(roundId), { outcome: "APPROVED", approvals: 2, rejections: 1, abstentions: 0 });
    for (const [v, verdict] of [[1, PASS], [2, PASS], [3, FAIL]]) {
      const vote = await f.registry.getVote(roundId, f.keys[v].address);
      assert.deepEqual([vote.cast, Number(vote.verdict), vote.evidenceHash], [true, verdict, evidence(v, "scan-1")]);
    }
    assert.deepEqual((await f.events("VoteRecorded")).map((e: any) => [e.validator, Number(e.verdict), e.evidenceHash, e.afterDecision]),
      [1, 2, 3].map((v) => [f.keys[v].address, v === 3 ? FAIL : PASS, evidence(v, "scan-1"), v === 3]));
    assert.deepEqual(await f.statusEvents(), ["P1:UNVERIFIED->VERIFIED:PASS_QUORUM"]);
  } finally { await f.close(); }
});

test("FAIL, ABSTAIN, FAIL revokes; the revoking round still records a late vote; nothing else is accepted", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now(), scan = { label: "scan-1", validFrom: t, validUntil: t + DAY };
    await f.attest(1, r, { ...scan, verdict: FAIL });
    await f.attest(3, r, { ...scan, verdict: ABSTAIN });
    assert.equal(await f.status(r), "UNVERIFIED");
    await f.attest(2, r, { ...scan, verdict: FAIL });
    const roundId = await f.roundOf(r, scan);
    assert.equal(await f.status(r), "REVOKED");
    assert.deepEqual(await f.round(roundId), { outcome: "REJECTED", approvals: 0, rejections: 2, abstentions: 1 });
    assert.equal(await f.registry.revokedRound(r), roundId);
    assert.deepEqual((await f.events("ReleaseRevoked")).map((e: any) => e.roundId), [roundId]);
    // FAIL, FAIL first: the third validator's later ABSTAIN still lands in the revoking round.
    const other = await f.register("npm:other-mcp");
    const to = await f.now(), late = { label: "scan-o", validFrom: to, validUntil: to + DAY };
    for (const v of [1, 2]) await f.attest(v, other, { ...late, verdict: FAIL });
    await f.attest(3, other, { ...late, verdict: ABSTAIN });
    assert.deepEqual(await f.round(await f.roundOf(other, late)), { outcome: "REJECTED", approvals: 0, rejections: 2, abstentions: 1 });
    const n = await f.now();
    assert.equal(await revertOf(() => f.attest(3, other, { label: "retry", verdict: PASS, validFrom: n, validUntil: n + DAY })), "TERMINAL_RELEASE");
  } finally { await f.close(); }
});

test("[C] fixed: a PASS/FAIL/ABSTAIN split asks for human review at once instead of locking the release for 30 days", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now(), split = { label: "scan-1", validFrom: t, validUntil: t + 30 * DAY };
    for (const [v, verdict] of [[1, PASS], [2, FAIL], [3, ABSTAIN]]) await f.attest(v, r, { ...split, verdict });
    const splitRound = await f.roundOf(r, split);
    assert.deepEqual(await f.round(splitRound), { outcome: "SPLIT", approvals: 1, rejections: 1, abstentions: 1 });
    assert.equal(await f.status(r), "UNVERIFIED");
    assert.equal(await f.registry.needsReview(r, P1), true);
    assert.deepEqual((await f.events("ReviewRequired")).map((e: any) => e.roundId), [splitRound]);
    // After review the validators re-scan right away; no ROUND_IN_PROGRESS.
    await f.advance(1); const n = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { label: "after-review", verdict: PASS, validFrom: n, validUntil: n + DAY });
    assert.equal(await f.status(r), "VERIFIED");
    assert.equal(await f.registry.needsReview(r, P1), false);
  } finally { await f.close(); }
});

test("[D] fixed: a junk first round does not lock out an honest round with another window", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    await f.attest(3, r, { label: "junk", verdict: ABSTAIN, validFrom: t, validUntil: t + 30 * DAY });
    for (const v of [1, 2]) await f.attest(v, r, { label: "real", verdict: PASS, validFrom: t, validUntil: t + DAY });
    assert.equal(await f.status(r), "VERIFIED");
    assert.equal((await f.decision(r)).roundId, await f.roundOf(r, { label: "real", verdict: PASS, validFrom: t, validUntil: t + DAY }));
  } finally { await f.close(); }
});

test("[A] fixed: after a quarantine one validator cannot reset a live VERIFIED decision or strand honest votes", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    let t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { label: "scan-1", verdict: PASS, validFrom: t, validUntil: t + DAY });
    await f.quarantine(1, r, "q1", 60);
    await f.advance(2); t = await f.now();
    const rescan = { label: "scan-2", verdict: PASS, validFrom: t, validUntil: t + DAY };
    for (const v of [1, 2]) await f.attest(v, r, rescan);
    await f.advance(65);
    assert.equal(await f.status(r), "VERIFIED");
    const live = (await f.decision(r)).roundId;
    t = await f.now();
    await f.attest(3, r, { label: "junk", verdict: ABSTAIN, validFrom: t, validUntil: t + 30 * DAY });
    assert.deepEqual([await f.status(r), (await f.decision(r)).roundId], ["VERIFIED", live], "an open junk round leaves the live decision alone");
    await f.advance(1); const honestFrom = await f.now();
    const honest = { label: "scan-3", verdict: PASS, validFrom: honestFrom, validUntil: honestFrom + DAY };
    await f.attest(1, r, honest);
    await f.advance(1); t = await f.now();
    await f.attest(3, r, { label: "junk-2", verdict: ABSTAIN, validFrom: t, validUntil: t + DAY });
    await f.attest(2, r, honest);
    assert.deepEqual(await f.decision(r), { status: "VERIFIED", roundId: await f.roundOf(r, honest), approvals: 2, rejections: 0 }, "validator 1's vote was not wiped");
  } finally { await f.close(); }
});

test("[B] fixed: one emergency quarantine per validator per release; an honest re-scan during it sticks", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    let t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { label: "scan-1", verdict: PASS, validFrom: t, validUntil: t + DAY });
    await f.quarantine(3, r, "q1", 30);
    assert.equal(await f.status(r), "QUARANTINED");
    // Honest validators re-scan during the quarantine. A validFrom equal to quarantinedAt would not count (strictly after).
    await f.advance(1); t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { label: "re-scan", verdict: PASS, validFrom: t, validUntil: t + DAY });
    const until = Number(await f.registry.quarantineUntil(r));
    await f.advanceTo(until - 1);
    assert.equal(await f.status(r), "QUARANTINED");
    await f.advance(1);
    assert.equal(await f.status(r), "VERIFIED");
    // The loop the review found: re-quarantine as soon as the first one ends, voiding the re-scan again.
    assert.equal(await revertOf(() => f.quarantine(3, r, "q2", 30)), "QUARANTINE_USED", "later findings go through FAIL votes");
    await f.quarantine(1, r, "q4", 5);
    assert.equal(await f.status(r), "QUARANTINED", "another validator keeps its own single brake");
    assert.deepEqual((await f.events("ReleaseQuarantined")).map((e: any) => e.validator), [f.keys[3].address, f.keys[1].address]);
  } finally { await f.close(); }
});

test("a stuck round retried with the same validFrom cannot later take over the live approval", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    const stuck = { label: "stuck", validFrom: t, validUntil: t + DAY };
    await f.attest(1, r, { ...stuck, verdict: PASS });
    await f.attest(2, r, { ...stuck, verdict: ABSTAIN });
    const retry = { label: "retry", verdict: PASS, validFrom: t, validUntil: t + 2 * DAY };
    for (const v of [1, 2]) await f.attest(v, r, retry);
    assert.equal(await f.status(r), "VERIFIED");
    await f.attest(3, r, { ...stuck, verdict: FAIL });
    assert.equal((await f.round(await f.roundOf(r, stuck))).outcome, "SPLIT");
    assert.deepEqual([await f.status(r), (await f.decision(r)).roundId], ["VERIFIED", await f.roundOf(r, retry)]);
    assert.deepEqual(await f.events("ReviewRequired"), [], "a split that is not live asks for no review");
    assert.equal(await f.registry.needsReview(r, P1), false);
  } finally { await f.close(); }
});

test("an approval of a scan taken before a quarantine is labelled STALE_APPROVAL, not PASS_QUORUM", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now(), early = { label: "early", verdict: PASS, validFrom: t, validUntil: t + DAY };
    await f.attest(1, r, early);
    await f.quarantine(3, r, "q1", 5);
    await f.advance(6);
    await f.attest(2, r, early);
    assert.equal(await f.status(r), "EXPIRED");
    assert.deepEqual(await f.statusEvents(), ["P1:UNVERIFIED->QUARANTINED:CANARY_EXFILTRATION", "P1:QUARANTINED->EXPIRED:STALE_APPROVAL"]);
  } finally { await f.close(); }
});

test("quarantineBySignature uses the V3 domain and shares the validator nonce with attestations", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    await f.attest(1, r, { label: "scan", verdict: PASS, validFrom: t, validUntil: t + DAY });
    const q = { releaseId: r, policyHash: P1, evidenceHash: id("q:signed"), reasonCode: CANARY, expiresAt: (await f.now()) + 60,
      validatorSetVersion: 1, nonce: Number(await f.registry.nonces(f.keys[1].address)), deadline: (await f.now()) + 60 };
    assert.equal(q.nonce, 1, "the attestation used nonce 0");
    const signature = await f.keys[1].signTypedData(f.domain, quarantineV3Types, q);
    await (await f.registry.quarantineBySignature(q, signature)).wait();
    assert.equal(await f.status(r), "QUARANTINED");
    assert.equal(await revertOf(() => f.registry.quarantineBySignature(q, signature)), "REPLAY");
    assert.equal(Number(await f.registry.nonces(f.keys[1].address)), 2);
  } finally { await f.close(); }
});

test("[E] fixed: two FAIL votes in a new round revoke a live VERIFIED release under the same policy", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { label: "scan-1", verdict: PASS, validFrom: t, validUntil: t + DAY });
    const n = await f.now();
    const finding = { label: "late-finding", verdict: FAIL, validFrom: n, validUntil: n + DAY };
    await f.attest(1, r, finding);
    assert.equal(await f.status(r), "VERIFIED", "one FAIL alone does not touch the live decision");
    await f.attest(3, r, finding);
    assert.equal(await f.status(r), "REVOKED");
    assert.deepEqual(await f.statusEvents(), ["P1:UNVERIFIED->VERIFIED:PASS_QUORUM", "P1:VERIFIED->REVOKED:FAIL_QUORUM"]);
  } finally { await f.close(); }
});

test("[V2] fixed: a renewal round decided before validUntil takes over with no unverified gap", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { label: "scan-1", verdict: PASS, validFrom: t, validUntil: t + DAY });
    await f.advanceTo(t + DAY - 100);
    const n = await f.now(), renewal = { label: "scan-2", verdict: PASS, validFrom: n, validUntil: n + DAY };
    await f.attest(1, r, renewal);
    assert.equal(await f.status(r), "VERIFIED", "still verified between the two renewal votes");
    await f.attest(2, r, renewal);
    await f.advanceTo(t + DAY + 10);
    assert.deepEqual(await f.decision(r), { status: "VERIFIED", roundId: await f.roundOf(r, renewal), approvals: 2, rejections: 0 });
  } finally { await f.close(); }
});

test("an older round that finishes late stays on record but does not replace a newer live decision", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    const older = { label: "old", verdict: PASS, validFrom: t, validUntil: t + DAY };
    await f.attest(1, r, older);
    await f.advance(1); const n = await f.now();
    const newer = { label: "new", verdict: PASS, validFrom: n, validUntil: n + DAY };
    for (const v of [2, 3]) await f.attest(v, r, newer);
    await f.attest(2, r, older);
    assert.equal((await f.round(await f.roundOf(r, older))).outcome, "APPROVED");
    assert.equal((await f.decision(r)).roundId, await f.roundOf(r, newer));
  } finally { await f.close(); }
});

test("[F] fixed: revocation binds the bytes; the same bytes cannot be registered or verified under another tool id", async () => {
  const f = await fixture();
  try {
    const twin = await f.register("npm:mail-mcp-twin", dig);
    const revoked = await f.register("npm:mail-mcp", dig);
    const t = await f.now();
    for (const v of [1, 2]) await f.attest(v, revoked, { label: "scan-1", verdict: FAIL, validFrom: t, validUntil: t + DAY });
    assert.deepEqual([await f.status(revoked), await f.status(twin)], ["REVOKED", "REVOKED"], "a twin registered before the revocation is revoked too");
    const revokingRound = await f.registry.revokedRound(revoked);
    assert.equal((await f.decision(revoked)).roundId, revokingRound, "a revoked decision names the revoking round");
    assert.deepEqual((await f.events("BytesRevoked")).map((e: any) => [e.artifactDigest, e.roundId]), [[dig, revokingRound]], "indexers learn about twins");
    const renamed = exactReleaseIdentity({ toolId: "npm:mail-mcp-renamed", artifactDigest: dig, manifestDigest: dig, toolSurfaceHash: surface });
    assert.equal(await revertOf(() => f.registry.registerRelease(renamed.toolId, dig, dig, surface)), "REVOKED_BYTES");
    const n = await f.now();
    assert.equal(await revertOf(() => f.attest(1, twin, { label: "x", verdict: PASS, validFrom: n, validUntil: n + DAY })), "TERMINAL_RELEASE");
  } finally { await f.close(); }
});

test("[G] partly fixed: a quarantine emits a release-wide ReleaseQuarantined event that names the validator", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    for (const policy of [P1, P2]) for (const v of [1, 2]) await f.attest(v, r, { policy, label: "scan", verdict: PASS, validFrom: t, validUntil: t + 100 });
    await f.quarantine(1, r, "q1", 10);
    assert.deepEqual([await f.status(r, P1), await f.status(r, P2)], ["QUARANTINED", "QUARANTINED"]);
    const [event] = await f.events("ReleaseQuarantined");
    assert.deepEqual([event.releaseId, event.validator, event.reasonCode, event.evidenceHash], [r, f.keys[1].address, CANARY, id("quarantine:q1")]);
    // Kept: the per-policy status event is still only for the policy named in the call.
    assert.deepEqual((await f.statusEvents()).slice(2), ["P1:VERIFIED->QUARANTINED:CANARY_EXFILTRATION"]);
  } finally { await f.close(); }
});

test("[H] fixed: syncExpiry labels a quorum that waited out a quarantine as QUARANTINE_ENDED", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    await f.quarantine(1, r, "q1", 30);
    await f.advance(2);
    const t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { label: "scan", verdict: PASS, validFrom: t, validUntil: t + DAY });
    assert.equal(await f.status(r), "QUARANTINED");
    await f.advance(40);
    assert.equal(await f.status(r), "VERIFIED");
    await (await f.registry.syncExpiry(r, P1)).wait();
    assert.deepEqual(await f.statusEvents(), ["P1:UNVERIFIED->QUARANTINED:CANARY_EXFILTRATION", "P1:QUARANTINED->VERIFIED:QUARANTINE_ENDED"]);
  } finally { await f.close(); }
});

test("[V1] kept: a FAIL quorum under any active policy revokes the release everywhere, now with a release-wide event", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { label: "scan-1", verdict: PASS, validFrom: t, validUntil: t + DAY });
    const n = await f.now();
    for (const v of [1, 3]) await f.attest(v, r, { policy: P2, label: "late", verdict: FAIL, validFrom: n, validUntil: n + DAY });
    assert.deepEqual([await f.status(r, P1), await f.status(r, P2)], ["REVOKED", "REVOKED"]);
    assert.deepEqual((await f.events("ReleaseRevoked")).map((e: any) => [e.releaseId, e.policyHash]), [[r, P2]]);
  } finally { await f.close(); }
});

test("[V4] kept: disabling a validator bumps the set version, so live approvals need a fresh round", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { label: "scan-1", verdict: PASS, validFrom: t, validUntil: t + DAY });
    await (await f.validators.disable(f.keys[3].address)).wait();
    assert.equal(await f.status(r), "EXPIRED");
  } finally { await f.close(); }
});

test("guard: signer, replay, evidence, domain, set version and owner checks", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:guard");
    const t = await f.now(), vote = { label: "g", verdict: PASS, validFrom: t, validUntil: t + DAY };
    assert.equal(await revertOf(() => f.attest(4, r, vote)), "NOT_VALIDATOR", "outsider signature");
    assert.equal(await revertOf(() => f.attest(1, r, { ...vote, evidenceHash: `0x${"0".repeat(64)}` })), "INVALID_VERDICT", "empty evidence");
    const payload = await f.payloadOf(1, r, vote);
    // A V2-style signature (domain version "1") recovers another address and is rejected.
    const v2Domain = attestationV2Domain(1337, await f.registry.getAddress());
    const v2Payload = { ...payload, reportRoot: payload.evidenceHash }; delete (v2Payload as any).evidenceHash;
    assert.equal(await revertOf(async () => f.registry.submitAttestation(payload, await f.keys[1].signTypedData(v2Domain, attestationV2Types, v2Payload))), "NOT_VALIDATOR");
    const signature = await f.keys[1].signTypedData(f.domain, attestationV3Types, payload);
    await (await f.registry.submitAttestation(payload, signature)).wait();
    assert.equal(await revertOf(() => f.registry.submitAttestation(payload, signature)), "REPLAY");
    assert.equal(await revertOf(() => f.attest(1, r, vote)), "DUPLICATE_VOTE", "same round, fresh nonce");
    await (await f.validators.disable(f.keys[3].address)).wait();
    const stale = { ...(await f.payloadOf(2, r, vote)), validatorSetVersion: 1 };
    assert.equal(await revertOf(async () => f.registry.submitAttestation(stale, await f.keys[2].signTypedData(f.domain, attestationV3Types, stale))), "STALE_VALIDATOR_SET");
    const outsider: any = f.registry.connect(await f.provider.getSigner(4));
    assert.equal(await revertOf(() => outsider.registerRelease(id("npm:intruder"), dig, dig, surface)), "ONLY_OWNER");
  } finally { await f.close(); }
});

test("read surface: a V2 client reads V3 releases, validators and getDecision unchanged", async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { label: "scan-1", verdict: PASS, validFrom: t, validUntil: t + DAY });
    const v2 = createReleaseRegistryV2(await f.registry.getAddress(), f.provider);
    const d = await v2.getDecision(r, P1);
    assert.deepEqual([Number(d.status), d.reportRoot, Number(d.validFrom), Number(d.validUntil), Number(d.validatorSetVersion), Number(d.approvals)],
      [1, await f.roundOf(r, { label: "scan-1", verdict: PASS, validFrom: t, validUntil: t + DAY }), t, t + DAY, 1, 2]);
    assert.equal((await v2.releases(r)).exists, true);
    assert.equal(await v2.validators(), await f.validators.getAddress());
    const abiNames = new Set((compiled.ReleaseRegistryV3.abi as any[]).filter((e: any) => e.type === "function" || e.type === "event").map((e: any) => e.name));
    for (const entry of releaseRegistryV3Abi) assert.ok(abiNames.has(entry.match(/^(?:function|event) (\w+)/)![1]), `SDK entry exists in the contract: ${entry}`);
  } finally { await f.close(); }
});
