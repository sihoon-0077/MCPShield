// Known-gap regression suite for ReleaseRegistryV2 (team backlog item A-03; not tracked in this repo).
//
// Every test titled "known gap (ADR-008 pending)" asserts a weakness that the UNMODIFIED
// contracts/src/ReleaseRegistryV2.sol shows today. These assertions do not say the behaviour
// is wanted. They pin it, so the planned ADR-008 contract fix has to flip each one on purpose:
// update the affected assertion in the same PR as the fix, never in a separate PR.
// ADR-008 is not written yet. It will sit next to docs/adr-007-registry-owner-governance.md as
// docs/adr-008-*.md; until then the titles and comments in this file are the list of gaps it must cover.
// A part of a gap test that no contract change can flip is marked "inherent" where it is asserted.
// The "guard:" tests pin exact revert reasons (strings as written in contracts/src) for behaviour
// that no listed gap targets, so the fix is expected to leave them green. A check that a gap fix
// would flip belongs in that gap's test, not in a guard.
//
// Determinism: each test gets a fresh in-process Ganache with a fixed genesis time and
// miner.timestampIncrement = 1, so every mined block is the previous block + 1 s, whatever the
// wall clock does. eth_call and eth_estimateGas run at the latest block's timestamp. The ethers
// request cache is off so a read straight after a write never returns a stale value.
// Time boundaries: ethers uses the eth_estimateGas result as the gas limit with no margin, and the
// estimate runs 1 s before the transaction executes. A step whose estimate and execution fall on
// different sides of a time boundary can take a different branch and fail as UNDECODED (out of gas)
// instead of with a clean reason. [C] and [D] vote at exactly validUntil, where both sides take the
// same branch; [B] lands a quarantine exactly at quarantineUntil with an explicit gasLimit. Any other
// step stays at least 2 s away from a boundary.
import assert from "node:assert/strict";
import { test } from "node:test";
import ganache from "ganache";
import { BrowserProvider, ContractFactory, Wallet, id } from "ethers";
import { compileReleaseRegistry } from "../../contracts/scripts/compile.js";
import { attestationV2Domain, attestationV2Types, exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";

const GAP = "known gap (ADR-008 pending)";
const DAY = 86_400;
const GENESIS = new Date("2026-01-01T00:00:00Z");
const STATUS = ["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"];
const PASS = 0, FAIL = 1, ABSTAIN = 2;
const dig = `0x${"a".repeat(64)}`, surface = `0x${"b".repeat(64)}`;
const P1 = id("policy-v1"), P2 = id("policy-v2");
const CANARY = id("CANARY_EXFILTRATION"), HOST_ESCAPE = id("HOST_ESCAPE_ATTEMPT");
const report = (label: string) => id(`report:${label}`);
const policyLabel = new Map([[P1, "P1"], [P2, "P2"]]);
const reasonLabel = new Map(["FRESH_SCAN", "PASS_QUORUM", "FAIL_QUORUM", "EXPIRY", "CANARY_EXFILTRATION", "HOST_ESCAPE_ATTEMPT", "DIGEST_MISMATCH"]
  .map((label) => [id(label), label]));
const compiled = Object.fromEntries(["ValidatorRegistry", "PolicyRegistry", "ReleaseRegistryV2"].map((name) => [name, compileReleaseRegistry(name)]));

type Vote = { policy?: string; root: string; verdict: number; validFrom: number; validUntil: number; setVersion?: number };
type QuarantineInput = { policy?: string; evidence: string; reason?: string; ttl: number; gasLimit?: number };
type StatusEvent = { policy: string; from: string; to: string; reason: string; evidenceRoot: string };

/** Exact require() reason of a reverted call, "NO_REVERT" when it succeeded. */
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
  const registry = await deploy("ReleaseRegistryV2", [owner.address, await validators.getAddress(), await policies.getAddress()]);
  const domain = attestationV2Domain(1337, await registry.getAddress());
  const now = async () => Number(BigInt((await chain.request({ method: "eth_getBlockByNumber", params: ["latest", false] })).timestamp));
  const advanceTo = async (timestamp: number) => { await chain.request({ method: "evm_mine", params: [timestamp] }); };
  const advance = async (seconds: number) => advanceTo((await now()) + seconds);
  const as = async (index: number): Promise<any> => registry.connect(await provider.getSigner(index));
  const register = async (toolId: string) => {
    const identity = exactReleaseIdentity({ toolId, artifactDigest: dig, manifestDigest: dig, toolSurfaceHash: surface });
    await (await registry.registerRelease(identity.toolId, dig, dig, surface)).wait();
    return identity.releaseId;
  };
  // Relayed by the owner, signed off-chain by keys[signer]; nonce and validator-set version are read from chain.
  const attest = async (signer: number, releaseId: string, vote: Vote) => {
    const payload = { releaseId, artifactDigest: dig, manifestDigest: dig, toolSurfaceDigest: surface, policyHash: vote.policy ?? P1,
      reportRoot: vote.root, verdict: vote.verdict, validFrom: vote.validFrom, validUntil: vote.validUntil,
      validatorSetVersion: vote.setVersion ?? Number(await validators.version()), nonce: Number(await registry.nonces(keys[signer].address)),
      deadline: (await now()) + 3600 };
    await (await registry.submitAttestation(payload, await keys[signer].signTypedData(domain, attestationV2Types, payload))).wait();
  };
  // expiresAt = latest block + ttl and the transaction is mined 1 s later, so the effective TTL is ttl - 1.
  // An explicit gasLimit skips eth_estimateGas (see "Time boundaries" above); a revert then fails at wait() as
  // CALL_EXCEPTION without a decoded reason, so use it only for a step that must succeed.
  const quarantine = async (index: number, releaseId: string, q: QuarantineInput) => {
    const validator = await as(index);
    const overrides = q.gasLimit === undefined ? {} : { gasLimit: q.gasLimit };
    await (await validator.quarantine(releaseId, q.policy ?? P1, q.evidence, q.reason ?? CANARY, (await now()) + q.ttl, overrides)).wait();
  };
  const decision = async (releaseId: string, policy = P1) => {
    const d = await registry.getDecision(releaseId, policy);
    return { status: STATUS[Number(d.status)], reportRoot: d.reportRoot as string, validFrom: Number(d.validFrom),
      validUntil: Number(d.validUntil), approvals: Number(d.approvals), rejections: Number(d.rejections) };
  };
  const status = async (releaseId: string, policy = P1) => (await decision(releaseId, policy)).status;
  const rawStatusEvents = async (): Promise<StatusEvent[]> => (await registry.queryFilter(registry.filters.ReleaseStatusChanged(), 0, "latest")).map((log: any) => ({
    policy: policyLabel.get(log.args.policyHash) ?? log.args.policyHash, from: STATUS[Number(log.args.previousStatus)],
    to: STATUS[Number(log.args.newStatus)], reason: reasonLabel.get(log.args.reasonCode) ?? log.args.reasonCode, evidenceRoot: log.args.evidenceRoot as string }));
  const statusEvents = async () => (await rawStatusEvents()).map((e) => `${e.policy}:${e.from}->${e.to}:${e.reason}`);
  return { chain, provider, keys, validators, policies, registry, now, advance, advanceTo, as, register, attest, quarantine,
    decision, status, rawStatusEvents, statusEvents, close: () => chain.disconnect() };
}

test(`[A] ${GAP}: after any quarantine one validator can reset a live VERIFIED round at will, with no ReleaseStatusChanged, and strand honest votes`, async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    let t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { root: report("scan-1"), verdict: PASS, validFrom: t, validUntil: t + DAY });
    assert.equal(await f.status(r), "VERIFIED");
    await f.quarantine(1, r, { evidence: id("evidence"), ttl: 60 });
    await f.advance(2); t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { root: report("scan-2"), verdict: PASS, validFrom: t, validUntil: t + DAY });
    assert.equal(await f.status(r), "QUARANTINED");
    await f.advance(65);
    assert.equal(await f.status(r), "VERIFIED", "re-verified once the quarantine TTL passed");
    const eventsBeforeReset = ["P1:UNVERIFIED->VERIFIED:PASS_QUORUM", "P1:VERIFIED->QUARANTINED:CANARY_EXFILTRATION", "P1:QUARANTINED->UNVERIFIED:FRESH_SCAN"];
    assert.deepEqual(await f.statusEvents(), eventsBeforeReset);
    // Gap: validator 3 alone opens a junk ABSTAIN round (validFrom > quarantinedAt) over the live VERIFIED round.
    t = await f.now();
    await f.attest(3, r, { root: report("junk-1"), verdict: ABSTAIN, validFrom: t, validUntil: t + 30 * DAY });
    assert.equal(await f.status(r), "UNVERIFIED");
    assert.deepEqual(await f.statusEvents(), eventsBeforeReset, "the effective VERIFIED -> UNVERIFIED reset emits no ReleaseStatusChanged");
    // Honest validators restart with a real report; validator 3 wipes it again between their two votes.
    await f.advance(1); const honestFrom = await f.now();
    const honest = { root: report("scan-3"), verdict: PASS, validFrom: honestFrom, validUntil: honestFrom + DAY };
    await f.attest(1, r, honest);
    await f.advance(1); t = await f.now();
    await f.attest(3, r, { root: report("junk-2"), verdict: ABSTAIN, validFrom: t, validUntil: t + DAY });
    await f.attest(2, r, honest);
    assert.equal(await revertOf(() => f.attest(1, r, honest)), "DUPLICATE_VOTE", "validator 1's wiped vote cannot be re-cast in the same round");
    assert.deepEqual(await f.decision(r), { status: "UNVERIFIED", reportRoot: report("scan-3"), validFrom: honestFrom, validUntil: honestFrom + DAY, approvals: 1, rejections: 0 });
  } finally { await f.close(); }
});

test(`[B] ${GAP}: the same validator re-quarantines in the very block each TTL ends, with arbitrary evidence, and each quarantine voids the live approval`, async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { root: report("scan-1"), verdict: PASS, validFrom: t, validUntil: t + DAY });
    assert.equal(await f.status(r), "VERIFIED");
    const quarantinedAt: number[] = [], quarantineUntil: number[] = [];
    for (let i = 0; i < 3; i++) {
      // For i > 0 the latest block is quarantineUntil[i - 1] - 1, so this transaction is mined exactly at quarantineUntil[i - 1].
      // The explicit gasLimit skips eth_estimateGas, which would run 1 s early, while the previous quarantine is still live.
      await f.quarantine(3, r, { evidence: id(`fake-evidence-${i}`), ttl: 5, gasLimit: 1_000_000 });
      assert.equal(await f.status(r), "QUARANTINED");
      quarantinedAt.push(Number(await f.registry.quarantinedAt(r))); quarantineUntil.push(Number(await f.registry.quarantineUntil(r)));
      await f.advanceTo(quarantineUntil[i] - 1);
      assert.equal(await f.status(r), "QUARANTINED", "still quarantined one second before quarantineUntil");
    }
    assert.deepEqual(quarantineUntil.map((until, i) => until - quarantinedAt[i]), [4, 4, 4], "effective TTL is 4 s (expiresAt = latest block + 5, mined 1 s later)");
    assert.deepEqual(quarantinedAt.slice(1), quarantineUntil.slice(0, 2), "zero cooldown: each new quarantine is mined in the block where the previous one ends");
    await f.advanceTo(quarantineUntil[2]);
    assert.deepEqual(await f.decision(r), { status: "EXPIRED", reportRoot: report("scan-1"), validFrom: t, validUntil: t + DAY, approvals: 2, rejections: 0 },
      "the 2-of-3 approval is still inside its validity window but never comes back");
    assert.deepEqual(await f.statusEvents(), ["P1:UNVERIFIED->VERIFIED:PASS_QUORUM", "P1:VERIFIED->QUARANTINED:CANARY_EXFILTRATION",
      "P1:QUARANTINED->QUARANTINED:CANARY_EXFILTRATION", "P1:QUARANTINED->QUARANTINED:CANARY_EXFILTRATION"]);
    assert.deepEqual((await f.rawStatusEvents()).slice(1).map((e) => e.evidenceRoot), [0, 1, 2].map((i) => id(`fake-evidence-${i}`)));
  } finally { await f.close(); }
});

test(`[C] ${GAP}: mixed PASS/FAIL/ABSTAIN votes leave the round stuck until its validUntil (up to 30 days)`, async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    const stuck = { root: report("scan-1"), validFrom: t, validUntil: t + 30 * DAY };
    for (const [v, verdict] of [[1, PASS], [2, FAIL], [3, ABSTAIN]]) await f.attest(v, r, { ...stuck, verdict });
    assert.deepEqual(await f.decision(r), { status: "UNVERIFIED", reportRoot: report("scan-1"), validFrom: t, validUntil: t + 30 * DAY, approvals: 1, rejections: 1 });
    const newScan = async () => { const n = await f.now(); return f.attest(1, r, { root: report("scan-2"), verdict: PASS, validFrom: n, validUntil: n + DAY }); };
    assert.equal(await revertOf(newScan), "ROUND_IN_PROGRESS");
    assert.equal(await revertOf(() => f.attest(3, r, { ...stuck, verdict: PASS })), "DUPLICATE_VOTE", "the ABSTAIN voter cannot change its vote");
    await f.advanceTo(t + 30 * DAY - 60);
    assert.equal(await f.status(r), "UNVERIFIED");
    assert.equal(await revertOf(newScan), "ROUND_IN_PROGRESS", "still locked one minute before validUntil");
    // The lock opens by validUntil: the status read flips at validUntil, and the first new vote is mined 1 s later.
    await f.advanceTo(t + 30 * DAY);
    assert.equal(await f.status(r), "EXPIRED");
    await newScan();
    assert.deepEqual(await f.decision(r), { status: "UNVERIFIED", reportRoot: report("scan-2"), validFrom: t + 30 * DAY, validUntil: t + 31 * DAY, approvals: 1, rejections: 0 });
  } finally { await f.close(); }
});

test(`[D] ${GAP}: a first mover locks a fresh release behind a junk reportRoot for up to 30 days`, async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    await f.attest(3, r, { root: report("junk"), verdict: ABSTAIN, validFrom: t, validUntil: t + 30 * DAY });
    for (const v of [1, 2]) {
      assert.equal(await revertOf(() => f.attest(v, r, { root: report("real-scan"), verdict: PASS, validFrom: t, validUntil: t + DAY })), "ROUND_IN_PROGRESS");
    }
    assert.deepEqual(await f.decision(r), { status: "UNVERIFIED", reportRoot: report("junk"), validFrom: t, validUntil: t + 30 * DAY, approvals: 0, rejections: 0 });
    // The lock does not need ABSTAIN: one PASS on one report blocks any other report the same way.
    const other = await f.register("npm:mail-mcp-2");
    const to = await f.now();
    await f.attest(1, other, { root: report("first"), verdict: PASS, validFrom: to, validUntil: to + DAY });
    const no = await f.now();
    assert.equal(await revertOf(() => f.attest(2, other, { root: report("second"), verdict: PASS, validFrom: no, validUntil: no + DAY })), "ROUND_IN_PROGRESS",
      "an undecided 1-vote round also locks out a different report");
    const honestScan = async (v: number) => { const n = await f.now(); return f.attest(v, r, { root: report("real-scan"), verdict: PASS, validFrom: n, validUntil: n + DAY }); };
    await f.advanceTo(t + 30 * DAY - 60);
    assert.equal(await f.status(r), "UNVERIFIED");
    assert.equal(await revertOf(() => honestScan(1)), "ROUND_IN_PROGRESS", "still locked one minute before the junk validUntil, even with a fresh validFrom");
    await f.advanceTo(t + 30 * DAY);
    assert.equal(await f.status(r), "EXPIRED");
    const n = await f.now();
    const honest = { root: report("real-scan"), verdict: PASS, validFrom: n, validUntil: n + DAY };
    for (const v of [1, 2]) await f.attest(v, r, honest);
    assert.deepEqual(await f.decision(r), { status: "VERIFIED", reportRoot: report("real-scan"), validFrom: t + 30 * DAY, validUntil: t + 31 * DAY, approvals: 2, rejections: 0 },
      "honest validators get in only once the junk round reaches its validUntil");
  } finally { await f.close(); }
});

test(`[E] ${GAP}: a live VERIFIED release has no FAIL-revoke path under the same policy before validUntil`, async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    const scan = { root: report("scan-1"), validFrom: t, validUntil: t + DAY };
    for (const v of [1, 2]) await f.attest(v, r, { ...scan, verdict: PASS });
    await f.attest(3, r, { ...scan, verdict: FAIL });
    assert.deepEqual(await f.decision(r), { status: "VERIFIED", reportRoot: report("scan-1"), validFrom: t, validUntil: t + DAY, approvals: 2, rejections: 1 });
    // This probes only the existing entry points (submitAttestation, quarantine). If ADR-008 closes the gap through a new
    // entry point, for example a dedicated revoke function, every assertion below keeps passing: update this test by hand
    // in the fix PR and assert the revoke through the new entry point.
    const n = await f.now();
    assert.equal(await revertOf(() => f.attest(1, r, { root: report("late-ai-finding"), verdict: FAIL, validFrom: n, validUntil: n + DAY })), "ROUND_IN_PROGRESS");
    assert.equal(await revertOf(() => f.attest(2, r, { ...scan, verdict: FAIL })), "DUPLICATE_VOTE", "a PASS voter cannot flip to FAIL");
    assert.equal(await revertOf(() => f.quarantine(1, r, { evidence: report("late-ai-finding"), reason: id("AI_SCORE"), ttl: 60 })), "NON_DETERMINISTIC_REASON");
    assert.equal(await f.status(r), "VERIFIED");
    assert.equal(await f.registry.revoked(r), false);
  } finally { await f.close(); }
});

test(`[F] ${GAP}: REVOKED binds the releaseId, not the bytes; the same bytes under a new toolId start fresh and verify`, async () => {
  const f = await fixture();
  try {
    const revoked = await f.register("npm:mail-mcp");
    let t = await f.now();
    for (const v of [1, 2]) await f.attest(v, revoked, { root: report("scan-1"), verdict: FAIL, validFrom: t, validUntil: t + DAY });
    assert.equal(await f.status(revoked), "REVOKED");
    const renamed = await f.register("npm:mail-mcp-renamed");
    assert.notEqual(renamed, revoked);
    const [a, b] = [await f.registry.releases(revoked), await f.registry.releases(renamed)];
    assert.deepEqual([b.artifactDigest, b.manifestDigest, b.toolSurfaceDigest], [a.artifactDigest, a.manifestDigest, a.toolSurfaceDigest]);
    assert.equal(await f.status(renamed), "UNVERIFIED");
    t = await f.now();
    for (const v of [1, 2]) await f.attest(v, renamed, { root: report("scan-x"), verdict: PASS, validFrom: t, validUntil: t + DAY });
    assert.deepEqual([await f.status(revoked), await f.status(renamed)], ["REVOKED", "VERIFIED"]);
    assert.deepEqual([await f.registry.revoked(revoked), await f.registry.revoked(renamed)], [true, false]);
  } finally { await f.close(); }
});

test(`[G] ${GAP}: event stream is incomplete; a P1 quarantine blocks P2 with no P2 event (and, inherently, time expiry emits nothing)`, async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    for (const [policy, label] of [[P1, "P1"], [P2, "P2"]]) {
      for (const v of [1, 2]) await f.attest(v, r, { policy, root: report(`scan-${label}`), verdict: PASS, validFrom: t, validUntil: t + 100 });
    }
    assert.deepEqual(await f.statusEvents(), ["P1:UNVERIFIED->VERIFIED:PASS_QUORUM", "P2:UNVERIFIED->VERIFIED:PASS_QUORUM"]);
    await f.quarantine(1, r, { evidence: id("evidence"), ttl: 10 });
    assert.deepEqual([await f.status(r, P1), await f.status(r, P2)], ["QUARANTINED", "QUARANTINED"]);
    const afterQuarantine = ["P1:UNVERIFIED->VERIFIED:PASS_QUORUM", "P2:UNVERIFIED->VERIFIED:PASS_QUORUM", "P1:VERIFIED->QUARANTINED:CANARY_EXFILTRATION"];
    assert.deepEqual(await f.statusEvents(), afterQuarantine, "no P2 event although P2 is effectively QUARANTINED");
    await f.advance(200);
    assert.deepEqual([await f.status(r, P1), await f.status(r, P2)], ["EXPIRED", "EXPIRED"]);
    // Inherent, not a fixable gap: expiry by time happens without a transaction, so no contract change can emit an event for it.
    // This assertion is expected to survive ADR-008; the mitigation is syncExpiry or an indexer that evaluates getDecision.
    // Only the missing P2 event above is a gap the fix should flip.
    assert.deepEqual(await f.statusEvents(), afterQuarantine, "VERIFIED/QUARANTINED -> EXPIRED by time emits nothing");
    await f.quarantine(2, r, { evidence: id("evidence-2"), ttl: 10 });
    assert.deepEqual((await f.statusEvents()).slice(afterQuarantine.length), ["P1:QUARANTINED->QUARANTINED:CANARY_EXFILTRATION"],
      "the stale stored status yields a QUARANTINED -> QUARANTINED event");
  } finally { await f.close(); }
});

test(`[H] ${GAP}: syncExpiry labels a quorum reached during quarantine as reason EXPIRY (UNVERIFIED -> VERIFIED)`, async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    await f.quarantine(1, r, { evidence: id("evidence"), ttl: 30 });
    await f.advance(2);
    const t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { root: report("scan"), verdict: PASS, validFrom: t, validUntil: t + DAY });
    assert.equal(await f.status(r), "QUARANTINED");
    await f.advance(40);
    assert.equal(await f.status(r), "VERIFIED");
    const stored = ["P1:UNVERIFIED->QUARANTINED:CANARY_EXFILTRATION", "P1:QUARANTINED->UNVERIFIED:FRESH_SCAN"];
    assert.deepEqual(await f.statusEvents(), stored, "no PASS_QUORUM event was ever emitted");
    await (await f.registry.syncExpiry(r, P1)).wait();
    assert.deepEqual((await f.statusEvents()).slice(stored.length), ["P1:UNVERIFIED->VERIFIED:EXPIRY"]);
    await (await f.registry.syncExpiry(r, P1)).wait();
    assert.equal((await f.statusEvents()).length, stored.length + 1, "a second sync is a no-op");
  } finally { await f.close(); }
});

test(`[V1] ${GAP}: two FAIL votes under another active policy revoke a live P1-VERIFIED release with no quarantine and no P1 event`, async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { root: report("scan-1"), verdict: PASS, validFrom: t, validUntil: t + DAY });
    assert.deepEqual([await f.status(r, P1), await f.status(r, P2)], ["VERIFIED", "UNVERIFIED"]);
    const n = await f.now();
    for (const v of [1, 3]) await f.attest(v, r, { policy: P2, root: report("late-ai"), verdict: FAIL, validFrom: n, validUntil: n + DAY });
    assert.deepEqual([await f.status(r, P1), await f.status(r, P2)], ["REVOKED", "REVOKED"]);
    assert.equal(await f.registry.revoked(r), true);
    assert.deepEqual(await f.statusEvents(), ["P1:UNVERIFIED->VERIFIED:PASS_QUORUM", "P2:UNVERIFIED->REVOKED:FAIL_QUORUM"]);
  } finally { await f.close(); }
});

test(`[V2] ${GAP}: a live VERIFIED round cannot be renewed before validUntil, so every renewal has an unverified gap`, async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    const live = { root: report("scan-1"), verdict: PASS, validFrom: t, validUntil: t + DAY };
    for (const v of [1, 2]) await f.attest(v, r, live);
    assert.equal(await f.status(r), "VERIFIED");
    const n = await f.now();
    assert.equal(await revertOf(() => f.attest(1, r, { root: report("scan-2"), verdict: PASS, validFrom: n, validUntil: n + DAY })), "ROUND_IN_PROGRESS", "new report");
    assert.equal(await revertOf(() => f.attest(1, r, { ...live, validFrom: n, validUntil: n + DAY })), "ROUND_IN_PROGRESS", "same report, new window");
    assert.equal(await revertOf(() => f.attest(1, r, live)), "DUPLICATE_VOTE", "identical round");
    await f.advanceTo(t + DAY + 10);
    assert.equal(await f.status(r), "EXPIRED");
    const n3 = await f.now();
    const renewal = { root: report("scan-2"), verdict: PASS, validFrom: n3, validUntil: n3 + DAY };
    await f.attest(1, r, renewal);
    assert.equal(await f.status(r), "UNVERIFIED", "between the first and second renewal vote the release is not admissible");
    await f.attest(2, r, renewal);
    assert.deepEqual(await f.decision(r), { status: "VERIFIED", reportRoot: report("scan-2"), validFrom: n3, validUntil: n3 + DAY, approvals: 2, rejections: 0 });
  } finally { await f.close(); }
});

test(`[V3] ${GAP}: after a quarantine honest validators can overwrite a junk round too; it is a race, not a lock`, async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    await f.quarantine(3, r, { evidence: id("evidence"), ttl: 5 });
    await f.advance(2);
    let t = await f.now();
    await f.attest(3, r, { root: report("junk"), verdict: ABSTAIN, validFrom: t, validUntil: t + 30 * DAY });
    await f.advance(1); t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { root: report("real"), verdict: PASS, validFrom: t, validUntil: t + DAY });
    await f.advance(10);
    assert.deepEqual(await f.decision(r), { status: "VERIFIED", reportRoot: report("real"), validFrom: t, validUntil: t + DAY, approvals: 2, rejections: 0 });
    assert.deepEqual(await f.statusEvents(), ["P1:UNVERIFIED->QUARANTINED:CANARY_EXFILTRATION", "P1:QUARANTINED->UNVERIFIED:FRESH_SCAN",
      "P1:UNVERIFIED->VERIFIED:PASS_QUORUM"]);
  } finally { await f.close(); }
});

test(`[V4] ${GAP}: disabling an uninvolved validator voids a live VERIFIED round and opens a FAIL-revoke path for the other two`, async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { root: report("scan-1"), verdict: PASS, validFrom: t, validUntil: t + DAY });
    let n = await f.now();
    assert.equal(await revertOf(() => f.attest(1, r, { root: report("x"), verdict: FAIL, validFrom: n, validUntil: n + DAY })), "ROUND_IN_PROGRESS", "locked before the disable");
    await (await f.validators.disable(f.keys[3].address)).wait();
    assert.equal(Number(await f.validators.version()), 2);
    assert.equal(await f.status(r), "EXPIRED");
    n = await f.now();
    await f.attest(1, r, { root: report("x"), verdict: FAIL, validFrom: n, validUntil: n + DAY });
    assert.equal(await f.status(r), "UNVERIFIED");
    await f.attest(2, r, { root: report("x"), verdict: FAIL, validFrom: n, validUntil: n + DAY });
    assert.equal(await f.status(r), "REVOKED");
    assert.deepEqual(await f.statusEvents(), ["P1:UNVERIFIED->VERIFIED:PASS_QUORUM", "P1:VERIFIED->UNVERIFIED:FRESH_SCAN", "P1:UNVERIFIED->REVOKED:FAIL_QUORUM"],
      "the disable itself (VERIFIED -> EXPIRED) emitted no status event");
  } finally { await f.close(); }
});

test(`[V5] ${GAP}: a second validator cannot extend or escalate a running quarantine, and after the TTL the release is EXPIRED`, async () => {
  const f = await fixture();
  try {
    const r = await f.register("npm:mail-mcp");
    const t = await f.now();
    for (const v of [1, 2]) await f.attest(v, r, { root: report("scan-1"), verdict: PASS, validFrom: t, validUntil: t + DAY });
    await f.quarantine(1, r, { evidence: id("evidence"), ttl: 5 });
    const until = Number(await f.registry.quarantineUntil(r));
    assert.equal(await revertOf(() => f.quarantine(2, r, { evidence: id("evidence-2"), reason: HOST_ESCAPE, ttl: 3600 })), "ALREADY_QUARANTINED");
    assert.equal(Number(await f.registry.quarantineUntil(r)), until);
    await f.advance(6);
    assert.deepEqual(await f.decision(r), { status: "EXPIRED", reportRoot: report("scan-1"), validFrom: t, validUntil: t + DAY, approvals: 2, rejections: 0 });
  } finally { await f.close(); }
});

// ROUND_IN_PROGRESS on an undecided round is the [C]/[D] lock and lives there; ALREADY_QUARANTINED for a second validator
// escalating a running quarantine is the [V5] gap and lives there. The P1 FAIL quorum's spill-over to P2 is [V1].
test("guard: exact reasons for non-validator signer, DUPLICATE_VOTE, TERMINAL_RELEASE, INVALID_RELEASE, same-validator ALREADY_QUARANTINED; per-policy votes are not summed", async () => {
  const f = await fixture();
  try {
    const a = await f.register("npm:guard-a");
    const t = await f.now();
    const vote = { root: report("a1"), verdict: PASS, validFrom: t, validUntil: t + DAY };
    assert.equal(await revertOf(() => f.attest(4, a, vote)), "NOT_VALIDATOR", "outsider signature");
    assert.equal(await revertOf(() => f.quarantine(4, a, { evidence: id("evidence"), ttl: 60 })), "NOT_VALIDATOR", "outsider quarantine");
    await f.attest(1, a, vote);
    assert.equal(await revertOf(() => f.attest(1, a, vote)), "DUPLICATE_VOTE", "same round, fresh nonce");
    // One PASS under P1 plus one PASS under P2 for the same bytes and report is not a quorum.
    await f.attest(2, a, { ...vote, policy: P2 });
    for (const policy of [P1, P2]) {
      assert.deepEqual(await f.decision(a, policy), { status: "UNVERIFIED", reportRoot: report("a1"), validFrom: t, validUntil: t + DAY, approvals: 1, rejections: 0 });
    }
    // One FAIL under P1 plus one FAIL under P2 does not revoke either.
    const b = await f.register("npm:guard-b");
    const tb = await f.now();
    const fail = { root: report("b1"), verdict: FAIL, validFrom: tb, validUntil: tb + DAY };
    await f.attest(1, b, fail);
    await f.attest(2, b, { ...fail, policy: P2 });
    assert.equal(await f.registry.revoked(b), false);
    for (const policy of [P1, P2]) {
      assert.deepEqual(await f.decision(b, policy), { status: "UNVERIFIED", reportRoot: report("b1"), validFrom: tb, validUntil: tb + DAY, approvals: 0, rejections: 1 });
    }
    await f.attest(3, b, fail);
    assert.equal(await f.status(b, P1), "REVOKED", "two FAIL votes under P1 revoke under P1");
    const nb = await f.now();
    assert.equal(await revertOf(() => f.attest(2, b, { root: report("b2"), verdict: PASS, validFrom: nb, validUntil: nb + DAY })), "TERMINAL_RELEASE");
    assert.equal(await revertOf(() => f.quarantine(1, b, { evidence: id("evidence"), ttl: 60 })), "INVALID_RELEASE");
    await f.quarantine(1, a, { evidence: id("evidence"), ttl: 60 });
    assert.equal(await revertOf(() => f.quarantine(1, a, { evidence: id("evidence"), ttl: 60 })), "ALREADY_QUARANTINED", "same validator, same evidence, while running");
  } finally { await f.close(); }
});

test("guard: ONLY_OWNER on admin entry points, rotation TIMELOCK, a disabled key stays NOT_VALIDATOR across rotation, stale set rejected", async () => {
  const f = await fixture();
  try {
    const outsider = await f.provider.getSigner(4);
    const [v1, v2, v3] = [1, 2, 3].map((i) => f.keys[i].address);
    const registry: any = f.registry.connect(outsider), validators: any = f.validators.connect(outsider), policies: any = f.policies.connect(outsider);
    assert.equal(await revertOf(() => registry.registerRelease(id("npm:intruder"), dig, dig, surface)), "ONLY_OWNER");
    assert.equal(await revertOf(() => validators.scheduleRotation([v1, v2, f.keys[4].address])), "ONLY_OWNER");
    assert.equal(await revertOf(() => validators.disable(v3)), "ONLY_OWNER");
    assert.equal(await revertOf(() => policies.publish(id("policy-x"), id("policy-x"))), "ONLY_OWNER");
    assert.equal(await revertOf(() => policies.deprecate(P1)), "ONLY_OWNER");
    assert.equal(await revertOf(() => validators.rotate()), "TIMELOCK", "nothing scheduled");
    await (await f.validators.disable(v3)).wait();
    assert.equal(Number(await f.validators.version()), 2);
    const r = await f.register("npm:guard-rotation");
    let t = await f.now();
    const vote = { root: report("g1"), verdict: PASS, validFrom: t, validUntil: t + DAY };
    assert.equal(await revertOf(() => f.attest(3, r, vote)), "NOT_VALIDATOR", "disabled key, current set version");
    assert.equal(await revertOf(() => f.quarantine(3, r, { evidence: id("evidence"), ttl: 60 })), "NOT_VALIDATOR", "disabled key quarantine");
    assert.equal(await revertOf(() => f.attest(1, r, { ...vote, setVersion: 1 })), "STALE_VALIDATOR_SET");
    // Re-adding the disabled key through a rotation is timelocked and does not re-enable it.
    await (await f.validators.scheduleRotation([v1, v2, v3])).wait();
    const rotationAt = Number(await f.validators.rotationAt());
    assert.equal(rotationAt, (await f.now()) + DAY);
    assert.equal(await revertOf(() => validators.rotate()), "TIMELOCK", "immediately after scheduling");
    await f.advanceTo(rotationAt - 60);
    assert.equal(await revertOf(() => validators.rotate()), "TIMELOCK", "one minute early");
    await f.advanceTo(rotationAt);
    await (await validators.rotate()).wait();
    assert.deepEqual([Number(await f.validators.version()), Number(await f.validators.rotationAt())], [3, 0]);
    assert.equal(await revertOf(() => validators.rotate()), "TIMELOCK", "a rotation is single-use");
    assert.equal(await f.validators.isActiveValidator(v3, 3), false);
    t = await f.now();
    const fresh = { root: report("g1"), verdict: PASS, validFrom: t, validUntil: t + DAY };
    assert.equal(await revertOf(() => f.attest(3, r, fresh)), "NOT_VALIDATOR", "disabled key re-added by rotation");
    assert.equal(await revertOf(() => f.attest(1, r, { ...fresh, setVersion: 2 })), "STALE_VALIDATOR_SET");
    await f.attest(1, r, fresh);
    assert.equal((await f.decision(r)).approvals, 1);
  } finally { await f.close(); }
});
