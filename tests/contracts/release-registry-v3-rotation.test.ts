// Key-rotation rehearsal (contracts/scripts/rotation-rehearsal.ts) against the unchanged ValidatorRegistry, PolicyRegistry
// and ReleaseRegistryV3. The run asserts every step itself and throws on the first mismatch; these tests pin the outcomes
// the mentoring Q&A quotes. One fresh in-process Ganache per scenario, evm time travel only.
import assert from "node:assert/strict";
import { before, test } from "node:test";
import { runRotationRehearsal, type RotationRehearsalResult } from "../../contracts/scripts/rotation-rehearsal.js";

const N = 2, DAY = 86_400;
const LEAKED_KEY_REVERTS = { leakedKeyVote: "NOT_VALIDATOR", leakedKeyQuarantine: "NOT_VALIDATOR", rotateEarly: "TIMELOCK" };
let result: RotationRehearsalResult;
before(async () => { result = await runRotationRehearsal({ liveReleases: N }); });

test("S1 normal rotation: 2 PASS per live release; the 1-day timelock blocks nothing, only the re-signatures do", () => {
  const s = result.scenarios.S1;
  assert.deepEqual([s.resignatures, s.timelockSeconds, s.rotatedAt, s.servedVersions, s.gatewayPinChangesPerCompany], [2 * N, DAY, s.rotationAt, [2], 1]);
  // Every transaction is its own 1-second block here, so the blocked window is exactly the re-signature transactions.
  assert.equal(s.blockedSeconds, s.resignatures);
  assert.deepEqual(s.reverts, { rotateEarly: "TIMELOCK", staleVote: "STALE_VALIDATOR_SET", removedKeyVote: "NOT_VALIDATOR" });
});

test("S2 leak caught before C is used: 4N re-signatures with the interim re-approval; 2N without it, but blocked through the whole timelock", () => {
  const { withInterimReapproval: a, withoutInterimReapproval: b } = result.scenarios.S2.caughtBeforeUse;
  assert.deepEqual([a.resignatures, a.blockedWindows.length, a.servedVersions, a.gatewayPinChangesPerCompany], [4 * N, 2, [2, 3], 2]);
  assert.equal(a.blockedSeconds, a.resignatures);
  assert.deepEqual([b.resignatures, b.blockedWindows.length, b.servedVersions, b.gatewayPinChangesPerCompany], [2 * N, 1, [3], 1]);
  assert.ok(b.blockedSeconds >= DAY, `blocked ${b.blockedSeconds} s`);
  for (const variant of [a, b]) assert.deepEqual([variant.quarantine, variant.reverts], [null, LEAKED_KEY_REVERTS]);
  assert.deepEqual(a.abstainProbe, { release: "release-1", votes: ["A PASS", "B ABSTAIN"], round: { outcome: "OPEN", approvals: 1, abstentions: 1 },
    status: "EXPIRED", sameRoundRetry: "DUPLICATE_VOTE", signaturesForThatRelease: 4, extraSignatures: 2, rolledBack: true });
});

test("S2 leak caught after C quarantined every live release: blocked about a day either way; the interim re-approval waits for the quarantine", () => {
  const { withInterimReapproval: a, withoutInterimReapproval: b } = result.scenarios.S2.caughtAfterQuarantine;
  assert.deepEqual([a.resignatures, a.servedVersions, a.gatewayPinChangesPerCompany], [4 * N, [2, 3], 2]);
  assert.deepEqual([b.resignatures, b.servedVersions, b.gatewayPinChangesPerCompany], [2 * N, [3], 1]);
  for (const variant of [a, b]) {
    assert.equal(variant.quarantine?.seconds, DAY);
    assert.ok(variant.blockedSeconds >= DAY, `blocked ${variant.blockedSeconds} s`);
    assert.deepEqual(variant.reverts, LEAKED_KEY_REVERTS);
  }
  // The interim rounds are decided at once, but the releases read VERIFIED only from the end of C's quarantine.
  assert.equal(a.blockedWindows[0].until, a.quarantine?.endsAt);
});

test("S3 two keys disabled: A's PASS alone decides nothing; blocked at least the 1-day timelock, then 2N re-signatures", () => {
  const s = result.scenarios.S3;
  assert.deepEqual([s.resignatures, s.votesThatCouldNotDecide, s.versions, s.servedVersions], [2 * N, N, [1, 2, 3, 4], [4]]);
  assert.ok(s.blockedSeconds >= DAY, `blocked ${s.blockedSeconds} s`);
  assert.deepEqual(s.reverts, { disabledKeyVotes: { B: "NOT_VALIDATOR", C: "NOT_VALIDATOR" }, rotateEarly: "TIMELOCK" });
});

test("gasUsed is measured for every governance transaction and the result is plain JSON", () => {
  const { gas } = result;
  // One first schedule and one rotate per rotation run (S1, four S2 variants, S3, gas step); disable in S2 x4, S3 x2, gas step.
  assert.deepEqual([gas.scheduleRotationFirst.count, gas.rotate.count, gas.disable.count, gas.quarantine.count], [7, 7, 7, 2 * N]);
  for (const kind of ["scheduleRotationFirst", "rotate", "disable", "quarantine"] as const) assert.ok(gas[kind].min > 0, kind);
  // rotate() leaves the pending slots filled, so a later schedule on the same registry costs far less than the first.
  assert.ok(gas.scheduleRotationAfterRotation < gas.scheduleRotationFirst.min * 0.6, `${gas.scheduleRotationAfterRotation} vs ${gas.scheduleRotationFirst.min}`);
  assert.ok(gas.disableBySlot.slot0 < gas.disableBySlot.slot1 && gas.disableBySlot.slot1 < gas.disableBySlot.slot2, JSON.stringify(gas.disableBySlot));
  assert.ok(gas.policyPublish > 0 && gas.policyDeprecate > 0);
  // The renewal vote that lands after the decision neither opens the round nor settles it, so it costs less than the vote
  // that opens the round and the one that decides it. C's first vote on the chain also writes its nonce for the first time.
  const renewal = gas.dailyRenewal;
  assert.ok(renewal.afterDecision > 0 && renewal.afterDecision < Math.min(renewal.opensRound, renewal.decides), JSON.stringify(renewal));
  assert.deepEqual([renewal.twoVotes, renewal.threeVotes], [renewal.opensRound + renewal.decides, renewal.twoVotes + renewal.afterDecision]);
  assert.ok(gas.firstRenewalAfterDecision > renewal.afterDecision, `${gas.firstRenewalAfterDecision} vs ${renewal.afterDecision}`);
  assert.equal(gas.resignatureVote.count, 16 * N, "S1 2N, S2 (4N + 2N) twice, S3 2N");
  assert.deepEqual(JSON.parse(JSON.stringify(result)), result);
});
