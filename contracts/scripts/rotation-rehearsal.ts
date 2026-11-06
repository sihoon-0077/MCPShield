// Key-rotation rehearsal for the mentoring Q&A (docs/mentoring-2026-10-response.md:117, :134). Per key event it measures
// how many PASS signatures the live releases need again, how many chain seconds some live release is not VERIFIED, and
// the local gasUsed of the governance transactions. The contracts are the deployed ones, unchanged.
// Each scenario runs on its own fresh in-process Ganache with the same genesis, accounts and setup. The clock moves only
// by evm_mine time travel; otherwise every transaction is its own block 1 s after the previous one, so the blocked
// seconds measured here are a lower bound for production.
import assert from "node:assert/strict";
import ganache from "ganache";
import solc from "solc";
import { BrowserProvider, ContractFactory, Wallet, id } from "ethers";
import { compileReleaseRegistry, type CompiledContract } from "./compile.js";
import { attestationV3Domain, attestationV3Types, exactReleaseIdentity, ROUND_OUTCOMES } from "../../packages/contracts-sdk/src/v3.js";

const DAY = 86_400;
const GENESIS = new Date("2026-01-01T00:00:00Z");
// Longer than every scenario, so each EXPIRED in S1-S3 comes from a validator-set version change, never from validUntil.
// The gas step's 1-day renewal rounds are the exception: release-1 runs out by time a few seconds before that step's rotate().
const VALIDITY = 30 * DAY;
const STATUS = ["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"];
const PASS = 0, ABSTAIN = 2;
// The owner deploys, governs and relays the validators' signed votes; the outsider only calls rotate().
const ROLES = ["owner", "A", "B", "C", "C'", "B'", "outsider"] as const;
type Role = (typeof ROLES)[number];
const POLICY = id("policy:key-rotation-rehearsal"), SPARE_POLICY = id("policy:key-rotation-rehearsal:spare");
const manifest = `0x${"a".repeat(64)}`, surface = `0x${"b".repeat(64)}`;
const CANARY = id("CANARY_EXFILTRATION");
// Ganache estimates gas at the latest block, 1 s before the transaction is mined. A transaction that must land at an
// exact second (rotate() at rotationAt, a quarantine with the full 1-day TTL) carries its own gas limit, because an
// estimate there would still see TIMELOCK or INVALID_TTL.
const FIXED_GAS_LIMIT = 200_000;

type Release = { name: string; releaseId: string; artifact: string };
type Validity = { validFrom: number; validUntil: number };
type Mined = { gasUsed: number; at: number; block: number };
type Check = (label: string, actual: unknown, expected: unknown) => void;
type Chain = Awaited<ReturnType<typeof freshChain>>;
type Restored = Awaited<ReturnType<Chain["restore"]>>;
type Signed = Awaited<ReturnType<Chain["sign"]>>;

async function revertOf(action: () => Promise<unknown>): Promise<string> {
  try { await action(); } catch (error: any) {
    return error?.info?.error?.data?.reason ?? error?.reason ?? `UNDECODED: ${error?.shortMessage ?? error?.message}`;
  }
  return "NO_REVERT";
}
const checker = (log: string[]): Check => (label, actual, expected) => { assert.deepEqual(actual, expected, label); log.push(label); };
const strict: Check = (label, actual, expected) => assert.deepEqual(actual, expected, label);
const stats = (values: number[]) => ({ count: values.length, min: Math.min(...values), max: Math.max(...values), total: values.reduce((a, b) => a + b, 0) });
type Stats = ReturnType<typeof stats>;
const merged = (list: Stats[]): Stats => ({ count: list.reduce((sum, s) => sum + s.count, 0), min: Math.min(...list.map((s) => s.min)),
  max: Math.max(...list.map((s) => s.max)), total: list.reduce((sum, s) => sum + s.total, 0) });

async function freshChain(compiled: Record<string, CompiledContract>, liveReleases: number) {
  const chain: any = ganache.provider({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: ROLES.length },
    chain: { time: GENESIS }, miner: { timestampIncrement: 1 } });
  const provider = new BrowserProvider(chain, 1337, { cacheTimeout: -1, staticNetwork: true });
  const close = async () => { provider.destroy(); await chain.disconnect(); };
  try {
    const keys = (Object.values(chain.getInitialAccounts()) as { secretKey: string }[]).map((a) => new Wallet(a.secretKey, provider));
    assert.deepEqual((await provider.send("eth_accounts", [])).map((a: string) => a.toLowerCase()), keys.map((k) => k.address.toLowerCase()), "account order");
    const key = (role: Role) => keys[ROLES.indexOf(role)];
    const address = (role: Role) => key(role).address;
    const set = (...roles: Role[]) => roles.map(address);
    const as = async (role: Role, contract: any) => contract.connect(await provider.getSigner(ROLES.indexOf(role)));
    const owner = await provider.getSigner(0);
    const deploy = async (name: string, args: unknown[]) => {
      const contract: any = await new ContractFactory(compiled[name].abi, compiled[name].bytecode, owner).deploy(...args);
      await contract.waitForDeployment(); return contract;
    };
    const validators = await deploy("ValidatorRegistry", [owner.address, set("A", "B", "C")]);
    const policies = await deploy("PolicyRegistry", [owner.address]);
    const registry = await deploy("ReleaseRegistryV3", [owner.address, await validators.getAddress(), await policies.getAddress()]);
    const domain = attestationV3Domain(1337, await registry.getAddress());
    const now = async () => Number(BigInt((await chain.request({ method: "eth_getBlockByNumber", params: ["latest", false] })).timestamp));
    const advanceTo = async (timestamp: number) => { await chain.request({ method: "evm_mine", params: [timestamp] }); };
    const mined = async (sent: Promise<any>): Promise<Mined> => {
      const receipt = await (await sent).wait();
      return { gasUsed: Number(receipt.gasUsed), at: (await provider.getBlock(receipt.blockNumber))!.timestamp, block: receipt.blockNumber };
    };
    const version = async () => Number(await validators.version());
    const validatorSet = async () => [await validators.validators(0), await validators.validators(1), await validators.validators(2)];
    const validity = async (): Promise<Validity> => { const t = await now(); return { validFrom: t, validUntil: t + VALIDITY }; };
    // Signed off-chain by the validator key and relayed by the owner, as the operator relayer does in production.
    const sign = async (role: Role, release: Release, verdict: number, w: Validity, label: string) => {
      const payload = { releaseId: release.releaseId, artifactDigest: release.artifact, manifestDigest: manifest, toolSurfaceDigest: surface,
        policyHash: POLICY, evidenceHash: id(`evidence:${role}:${release.name}:${label}`), verdict, ...w, validatorSetVersion: await version(),
        nonce: Number(await registry.nonces(address(role))), deadline: (await now()) + 3600 };
      return { payload, signature: await key(role).signTypedData(domain, attestationV3Types, payload) };
    };
    const submit = (vote: { payload: object; signature: string }) => mined(registry.submitAttestation(vote.payload, vote.signature));
    const attest = async (role: Role, release: Release, verdict: number, w: Validity, label: string) => submit(await sign(role, release, verdict, w, label));
    const decision = async (release: Release) => {
      const d = await registry.getDecision(release.releaseId, POLICY);
      return { status: STATUS[Number(d.status)], roundId: d.reportRoot as string, version: Number(d.validatorSetVersion), approvals: Number(d.approvals) };
    };
    const round = async (release: Release, w: Validity, setVersion: number) => {
      const r = await registry.getRound(await registry.roundIdOf(release.releaseId, POLICY, w.validFrom, w.validUntil, setVersion));
      return { outcome: ROUND_OUTCOMES[Number(r.outcome)] as string, approvals: Number(r.approvals), abstentions: Number(r.abstentions) };
    };
    const releases: Release[] = [];
    const statuses = async () => { const out: string[] = []; for (const r of releases) out.push((await decision(r)).status); return out; };
    const all = <T>(value: T) => releases.map(() => value);
    // Both validators re-sign every live release in a fresh round under the current set version. Each works through its
    // own queue, so the second validator's votes decide. A release under a quarantine that is still running reads
    // QUARANTINED until it ends and VERIFIED from then on; `at` is the second from which every live release reads VERIFIED.
    const restore = async (pair: [Role, Role], label: string, check = strict) => {
      const w = await validity(), votes: Mined[] = [];
      for (const role of pair) for (const r of releases) votes.push(await attest(role, r, PASS, w, label));
      const setVersion = await version(), t = await now(), decisions: unknown[][] = [], expected: unknown[][] = [], verifiedFrom: number[] = [];
      for (const r of releases) {
        const d = await decision(r), held = Number(await registry.quarantineUntil(r.releaseId));
        decisions.push([d.status, d.version, d.approvals]);
        expected.push([held > t ? "QUARANTINED" : "VERIFIED", setVersion, 2]);
        verifiedFrom.push(Math.max(Number((await registry.getRound(d.roundId)).decidedAt), held));
      }
      const waits = expected.some(([status]) => status === "QUARANTINED") ? " once its quarantine ends" : "";
      check(`${label}: ${pair.join(" + ")} PASS make every live release VERIFIED under set version ${setVersion}${waits}`, decisions, expected);
      return { by: [...pair], votes: votes.length, gas: votes.map((v) => v.gasUsed), version: setVersion, at: Math.max(...verifiedFrom) };
    };
    const publish = await mined(policies.publish(POLICY, id("policy-document:key-rotation-rehearsal")));
    const registrations: Mined[] = [];
    for (let i = 1; i <= liveReleases; i++) {
      const name = `release-${i}`, artifact = id(`artifact:${name}`);
      const identity = exactReleaseIdentity({ toolId: `npm:rotation-rehearsal-${i}`, artifactDigest: artifact, manifestDigest: manifest, toolSurfaceHash: surface });
      registrations.push(await mined(registry.registerRelease(identity.toolId, artifact, manifest, surface)));
      releases.push({ name, releaseId: identity.releaseId, artifact });
    }
    const approval = await restore(["A", "B"], "initial-scan");
    assert.equal(approval.version, 1, "setup: every live release is VERIFIED under set version 1");
    const setup = { accounts: Object.fromEntries(ROLES.map((role) => [role, address(role)])), hardfork: chain.getOptions().chain.hardfork as string,
      steps: "publish one policy, register every live release, A PASS then B PASS on each",
      gas: { policyPublish: publish.gasUsed, registerRelease: stats(registrations.map((r) => r.gasUsed)), approvalVote: stats(approval.gas) } };
    return { chain, validators, policies, registry, releases, setup, address, set, as, now, advanceTo, mined, version, validatorSet, validity,
      sign, submit, attest, decision, round, statuses, all, restore, close };
  } catch (error) { await close(); throw error; }
}

const blockedWindow = (brokenBy: string, broken: Mined, restored: Restored) =>
  ({ brokenBy, from: broken.at, until: restored.at, seconds: restored.at - broken.at, restoredUnderVersion: restored.version });
const outcome = (c: Chain, restorations: Restored[], blocked: ReturnType<typeof blockedWindow>[]) => {
  const resignatures = restorations.reduce((sum, r) => sum + r.votes, 0);
  return { resignatures, resignaturesPerRelease: resignatures / c.releases.length, blockedSeconds: blocked.reduce((sum, w) => sum + w.seconds, 0),
    blockedWindows: blocked, servedVersions: restorations.map((r) => r.version), gatewayPinChangesPerCompany: restorations.length,
    restoredBy: restorations.map((r) => r.by), resignatureGas: stats(restorations.flatMap((r) => r.gas)) };
};

// scheduleRotation by the owner, a rotate() that fails 60 s early, then the outsider's rotate() at exactly rotationAt.
// pending(secondsLeft) checks the scenario's state right after scheduling, at every extra stop, 60 s before and 1 s
// before rotationAt.
async function rotateAfterTimelock(c: Chain, next: Role[], check: Check, pending: (secondsLeft: number) => Promise<void>, stops: number[] = []) {
  const before = await c.version();
  const schedule = await c.mined(c.validators.scheduleRotation(c.set(...next)));
  const rotationAt = Number(await c.validators.rotationAt());
  check("rotationAt is the scheduleRotation block + 1 day", rotationAt - schedule.at, DAY);
  await pending(rotationAt - (await c.now()));
  let early = "";
  for (const at of [...new Set([...stops, rotationAt - 60, rotationAt - 1])].sort((a, b) => a - b)) {
    await c.advanceTo(at);
    if (at === rotationAt - 60) {
      early = await revertOf(async () => (await c.as("outsider", c.validators)).rotate());
      check("rotate() 60 s before rotationAt reverts TIMELOCK", early, "TIMELOCK");
    }
    await pending(rotationAt - at);
  }
  const rotate = await c.mined((await c.as("outsider", c.validators)).rotate({ gasLimit: FIXED_GAS_LIMIT }));
  check("the outsider's rotate() lands at exactly rotationAt", rotate.at, rotationAt);
  check(`rotate() raises the set version to ${before + 1} and installs ${next.join(", ")}`, [await c.version(), ...(await c.validatorSet())], [before + 1, ...c.set(...next)]);
  check("right after rotate() every live release reads EXPIRED", await c.statuses(), c.all("EXPIRED"));
  return { schedule, rotationAt, rotate, early, timelockSeconds: rotationAt - schedule.at };
}

async function normalRotation(c: Chain) {
  const checks: string[] = [], check = checker(checks), signedEarlier: { vote?: Signed } = {};
  const rotation = await rotateAfterTimelock(c, ["A", "B", "C'"], check, async (left) => {
    check(`${left} s before rotationAt: set version 1 and every live release VERIFIED`, [await c.version(), await c.statuses()], [1, c.all("VERIFIED")]);
    if (left === 60) signedEarlier.vote = await c.sign("A", c.releases[0], PASS, await c.validity(), "signed-before-rotation");
  });
  const staleVote = await revertOf(() => c.submit(signedEarlier.vote!));
  check("A's vote signed for set version 1 before the rotation is rejected STALE_VALIDATOR_SET", staleVote, "STALE_VALIDATOR_SET");
  const removedKeyVote = await revertOf(async () => c.attest("C", c.releases[0], PASS, await c.validity(), "removed-key"));
  check("C's vote for set version 2 is rejected NOT_VALIDATOR", removedKeyVote, "NOT_VALIDATOR");
  const restored = await c.restore(["A", "C'"], "after-rotation", check);
  return { title: "normal rotation C -> C'", versions: [1, 2], versionChanges: 1, timelockSeconds: rotation.timelockSeconds,
    scheduledAt: rotation.schedule.at, rotationAt: rotation.rotationAt, rotatedAt: rotation.rotate.at, rotatedBy: "outsider",
    ...outcome(c, [restored], [blockedWindow("rotate() to set version 2", rotation.rotate, restored)]),
    reverts: { rotateEarly: rotation.early, staleVote, removedKeyVote },
    gas: { scheduleRotation: rotation.schedule.gasUsed, rotate: rotation.rotate.gasUsed }, checks };
}

// Runs on an evm_snapshot that is rolled back, so the S2 counts stay those of a clean interim re-approval. With C
// disabled, one ABSTAIN between A and B leaves the round OPEN, B cannot vote again in it, and only a new round verifies.
async function abstainProbe(c: Chain, check: Check) {
  const release = c.releases[0], snapshot = await c.chain.request({ method: "evm_snapshot", params: [] });
  const w = await c.validity(), setVersion = await c.version(), votes = [];
  votes.push(await c.attest("A", release, PASS, w, "probe"), await c.attest("B", release, ABSTAIN, w, "probe"));
  const round = await c.round(release, w, setVersion), status = (await c.decision(release)).status;
  check(`A PASS + B ABSTAIN under set version ${setVersion}: the round stays OPEN`, round, { outcome: "OPEN", approvals: 1, abstentions: 1 });
  check("A PASS + B ABSTAIN: the release stays EXPIRED", status, "EXPIRED");
  const sameRoundRetry = await revertOf(() => c.attest("B", release, PASS, w, "probe-retry"));
  check("B cannot vote again in that round (DUPLICATE_VOTE)", sameRoundRetry, "DUPLICATE_VOTE");
  const retry = await c.validity();
  votes.push(await c.attest("A", release, PASS, retry, "probe-new-round"), await c.attest("B", release, PASS, retry, "probe-new-round"));
  check("a new round with A PASS + B PASS verifies it", (await c.decision(release)).status, "VERIFIED");
  check("the probe is rolled back", await c.chain.request({ method: "evm_revert", params: [snapshot] }), true);
  check("after the rollback the release reads EXPIRED again", (await c.decision(release)).status, "EXPIRED");
  return { release: release.name, votes: ["A PASS", "B ABSTAIN"], round, status, sameRoundRetry,
    signaturesForThatRelease: votes.length, extraSignatures: votes.length - 2, rolledBack: true };
}

// quarantinedFirst: before the leak is caught, the attacker uses C's one emergency brake on every live release with the
// longest TTL the contract allows. disable(C) does not lift it, and V3 has no call that does.
async function leakedKey(c: Chain, interim: boolean, quarantinedFirst: boolean) {
  const checks: string[] = [], check = checker(checks), [first] = c.releases, brakes: Mined[] = [];
  if (quarantinedFirst) for (const r of c.releases) brakes.push(await c.mined((await c.as("C", c.registry)).quarantine(r.releaseId, POLICY,
    id(`quarantine:leaked-key:${r.name}`), CANARY, (await c.now()) + 1 + DAY, { gasLimit: FIXED_GAS_LIMIT })));
  const until = await Promise.all(c.releases.map(async (r) => Number(await c.registry.quarantineUntil(r.releaseId))));
  // A live release reads QUARANTINED while C's quarantine on it runs, otherwise `rest`.
  const expected = async (rest: string) => { const t = await c.now(); return until.map((u) => (u > t ? "QUARANTINED" : rest)); };
  if (quarantinedFirst) check("C's quarantine holds every live release QUARANTINED for 1 day, the longest TTL",
    [await c.statuses(), brakes.map((b, i) => until[i] - b.at)], [c.all("QUARANTINED"), c.all(DAY)]);
  const disable = await c.mined(c.validators.disable(c.address("C")));
  check("disable(C) raises the set version to 2 at once", await c.version(), 2);
  check(`right after disable(C) every live release reads ${quarantinedFirst ? "QUARANTINED: disable(C) does not lift C's quarantine" : "EXPIRED"}`,
    await c.statuses(), await expected("EXPIRED"));
  const leakedVote = await revertOf(async () => c.attest("C", first, PASS, await c.validity(), "leaked-key"));
  check("C's vote is rejected NOT_VALIDATOR", leakedVote, "NOT_VALIDATOR");
  const leakedQuarantine = await revertOf(async () =>
    (await c.as("C", c.registry)).quarantine(first.releaseId, POLICY, id("quarantine:leaked-key"), CANARY, (await c.now()) + 3600));
  check("C's quarantine is rejected NOT_VALIDATOR", leakedQuarantine, "NOT_VALIDATOR");
  const restorations: Restored[] = [], blocked: ReturnType<typeof blockedWindow>[] = [];
  const broken = quarantinedFirst ? brakes[0] : disable;
  const brokenBy = quarantinedFirst ? "C's quarantine on every live release, then disable(C) to set version 2" : "disable(C) to set version 2";
  const probe = interim && !quarantinedFirst ? await abstainProbe(c, check) : null;
  if (interim) {
    const reapproved = await c.restore(["A", "B"], "interim-reapproval", check);
    restorations.push(reapproved); blocked.push(blockedWindow(brokenBy, broken, reapproved));
  }
  // With C's quarantine, the extra stops are the second before and the second at which the last quarantine ends.
  const rest = interim ? "VERIFIED" : "EXPIRED", lastEnd = Math.max(...until);
  const label = async (left: number) => quarantinedFirst ? `${left} s before rotationAt: set version 2, live releases ${(await expected(rest)).join(" / ")}`
    : `${left} s before rotationAt: set version 2 and every live release ${interim ? "VERIFIED by the interim re-approval" : "still EXPIRED"}`;
  const rotation = await rotateAfterTimelock(c, ["A", "B", "C'"], check, async (left) =>
    check(await label(left), [await c.version(), await c.statuses()], [2, await expected(rest)]), quarantinedFirst ? [lastEnd - 1, lastEnd] : []);
  const restored = await c.restore(["A", "C'"], "after-rotation", check);
  restorations.push(restored);
  blocked.push(interim ? blockedWindow("rotate() to set version 3", rotation.rotate, restored)
    : blockedWindow(`${brokenBy}, then rotate() to set version 3`, broken, restored));
  const caught = quarantinedFirst ? "caught after C quarantined every live release for 1 day" : "caught before C is used";
  return { title: `leaked key C ${caught}; ${interim ? "A + B re-approve at once" : "no re-approval until the rotation"}`,
    versions: [1, 2, 3], versionChanges: 2, timelockSeconds: rotation.timelockSeconds,
    quarantine: quarantinedFirst ? { by: "C", seconds: until[0] - brakes[0].at, endsAt: lastEnd, gas: stats(brakes.map((b) => b.gasUsed)) } : null,
    ...outcome(c, restorations, blocked),
    reverts: { leakedKeyVote: leakedVote, leakedKeyQuarantine: leakedQuarantine, rotateEarly: rotation.early }, abstainProbe: probe,
    gas: { disable: disable.gasUsed, scheduleRotation: rotation.schedule.gasUsed, rotate: rotation.rotate.gasUsed }, checks };
}

async function twoKeysDisabled(c: Chain) {
  const checks: string[] = [], check = checker(checks);
  const disableB = await c.mined(c.validators.disable(c.address("B")));
  check("disable(B): set version 2 and every live release EXPIRED", [await c.version(), await c.statuses()], [2, c.all("EXPIRED")]);
  const disableC = await c.mined(c.validators.disable(c.address("C")));
  const setVersion = await c.version(), active = async (role: Role): Promise<boolean> => c.validators.isActiveValidator(c.address(role), setVersion);
  check("disable(C): set version 3 and only A is active", [setVersion, await active("A"), await active("B"), await active("C")], [3, true, false, false]);
  const disabledVotes: Record<string, string> = {};
  for (const role of ["B", "C"] as const) disabledVotes[role] = await revertOf(async () => c.attest(role, c.releases[0], PASS, await c.validity(), "disabled-key"));
  check("B's and C's votes are rejected NOT_VALIDATOR", disabledVotes, { B: "NOT_VALIDATOR", C: "NOT_VALIDATOR" });
  const alone = await c.validity();
  for (const r of c.releases) await c.attest("A", r, PASS, alone, "alone");
  const aloneRounds = async () => { const out = []; for (const r of c.releases) out.push(await c.round(r, alone, setVersion)); return out; };
  check("A's PASS alone leaves every round OPEN", await aloneRounds(), c.all({ outcome: "OPEN", approvals: 1, abstentions: 0 }));
  check("A's PASS alone leaves every live release EXPIRED", await c.statuses(), c.all("EXPIRED"));
  const rotation = await rotateAfterTimelock(c, ["A", "B'", "C'"], check, async (left) => check(
    `${left} s before rotationAt: set version 3, A's rounds still OPEN, every live release EXPIRED`,
    [await c.version(), (await aloneRounds()).map((r) => r.outcome), await c.statuses()], [3, c.all("OPEN"), c.all("EXPIRED")]));
  const restored = await c.restore(["B'", "C'"], "after-rotation", check);
  const blocked = blockedWindow("disable(B) and disable(C) to set version 3, then rotate() to set version 4", disableB, restored);
  check("blocked for at least the 1-day timelock", blocked.seconds >= DAY, true);
  return { title: "two keys disabled (B and C), rotation to B' and C'", versions: [1, 2, 3, 4], versionChanges: 3,
    timelockSeconds: rotation.timelockSeconds, ...outcome(c, [restored], [blocked]), votesThatCouldNotDecide: c.releases.length,
    reverts: { disabledKeyVotes: disabledVotes, rotateEarly: rotation.early },
    gas: { disable: [disableB.gasUsed, disableC.gasUsed], scheduleRotation: rotation.schedule.gasUsed, rotate: rotation.rotate.gasUsed }, checks };
}

// Gas only, on its own chain. A separate policy, so the policy every scenario verifies under is never deprecated. Then a
// daily renewal round on a VERIFIED release. Then a first scheduleRotation, its rotate() and a second scheduleRotation on
// the same registry: rotate() leaves the pending slots filled, so only a registry's first schedule pays for writing
// them. Last, disable() of the key in slot 0.
async function gasStep(c: Chain) {
  const checks: string[] = [], check = checker(checks);
  const publish = await c.mined(c.policies.publish(SPARE_POLICY, id("policy-document:key-rotation-rehearsal:spare")));
  check("publish() activates the spare policy", await c.policies.active(SPARE_POLICY), true);
  const deprecate = await c.mined(c.policies.deprecate(SPARE_POLICY));
  check("deprecate() turns off only the spare policy", [await c.policies.active(SPARE_POLICY), await c.policies.active(POLICY)], [false, true]);
  check("set version 1 and every live release still VERIFIED", [await c.version(), await c.statuses()], [1, c.all("VERIFIED")]);
  // The validator app caps every round at 24 h (apps/validator/src/v3.ts:21), so a live release stays VERIFIED only if
  // the validators approve it again in a new round every day. Here that renewal is a 1-day round on a release that is
  // already VERIFIED, under the same set version: the first PASS opens the round, the second decides it, and the
  // operator still relays the third, which lands after the decision. C has not voted on this chain before (the setup
  // uses A and B), so the first renewal also pays C's first nonce write; the second renewal is the cost that repeats.
  const [renewed] = c.releases;
  const renew = async (label: string) => {
    const from = await c.now(), w = { validFrom: from, validUntil: from + DAY }, votes: Mined[] = [];
    for (const role of ["A", "B", "C"] as const) votes.push(await c.attest(role, renewed, PASS, w, label));
    const d = await c.decision(renewed);
    check(`${label}: the renewal round becomes the live round, VERIFIED, with C's vote after the decision on record (3 PASS)`,
      [d.status, d.roundId, d.approvals], ["VERIFIED", await c.registry.roundIdOf(renewed.releaseId, POLICY, w.validFrom, w.validUntil, 1), 3]);
    const [opensRound, decides, afterDecision] = votes.map((v) => v.gasUsed);
    return { opensRound, decides, afterDecision };
  };
  const firstRenewal = await renew("first daily renewal"), dailyRenewal = await renew("second daily renewal");
  const first = await rotateAfterTimelock(c, ["A", "B", "C'"], check, async () => {});
  const again = await c.mined(c.validators.scheduleRotation(c.set("A", "B'", "C'")));
  check("a second scheduleRotation on the same registry sets rotationAt 1 day ahead", Number(await c.validators.rotationAt()) - again.at, DAY);
  check("A holds slot 0", await c.validators.validators(0), c.address("A"));
  const disableA = await c.mined(c.validators.disable(c.address("A")));
  check("disable(A) raises the set version to 3", await c.version(), 3);
  return { title: "gas only: spare policy publish and deprecate; two daily renewal rounds; first and second scheduleRotation on one registry; disable of the slot-0 key",
    policyPublish: publish.gasUsed, policyDeprecate: deprecate.gasUsed, firstRenewal, dailyRenewal,
    scheduleRotationFirst: first.schedule.gasUsed, rotate: first.rotate.gasUsed,
    scheduleRotationAfterRotation: again.gasUsed, disableSlot0: disableA.gasUsed, checks };
}

export async function runRotationRehearsal(options: { liveReleases?: number } = {}) {
  const liveReleases = options.liveReleases ?? 2;
  if (!Number.isSafeInteger(liveReleases) || liveReleases < 1 || liveReleases > 50) throw new Error("LIVE_RELEASES_OUT_OF_RANGE");
  // solc-js blocks the event loop for seconds, so compile before any in-process chain runs.
  const compiled = Object.fromEntries(["ValidatorRegistry", "PolicyRegistry", "ReleaseRegistryV3"].map((name) => [name, compileReleaseRegistry(name)]));
  const fresh = async <T>(name: string, scenario: (c: Chain) => Promise<T>) => {
    try {
      const c = await freshChain(compiled, liveReleases);
      try { return { setup: c.setup, result: await scenario(c) }; } finally { await c.close(); }
    } catch (error: any) { throw new Error(`${name}: ${error?.message ?? error}`, { cause: error }); }
  };
  // The chains share nothing, so they run side by side; every chain is closed before a failure is reported.
  const pending = [fresh("S1", normalRotation),
    fresh("S2 caught before use, with the interim re-approval", (c) => leakedKey(c, true, false)),
    fresh("S2 caught before use, without the interim re-approval", (c) => leakedKey(c, false, false)),
    fresh("S2 caught after C's quarantine, with the interim re-approval", (c) => leakedKey(c, true, true)),
    fresh("S2 caught after C's quarantine, without the interim re-approval", (c) => leakedKey(c, false, true)),
    fresh("S3", twoKeysDisabled), fresh("gas step", gasStep)] as const;
  for (const settled of await Promise.allSettled(pending)) if (settled.status === "rejected") throw settled.reason;
  const [s1, { result: a }, { result: b }, { result: qa }, { result: qb }, { result: s3 }, { result: g }] = await Promise.all(pending);
  const runs = [s1.result, a, b, qa, qb, s3];
  return {
    schema: "mcpshield.key-rotation-rehearsal/1",
    liveReleases,
    isolation: "fresh chain per scenario: S1, the four S2 variants, S3 and the gas step each deploy and set up their own in-process Ganache, run side by side; nothing is shared",
    chain: { engine: `ganache ${ganache.__experimental_info().version} in-process provider, no RPC server`, hardfork: s1.setup.hardfork, chainId: 1337,
      genesis: GENESIS.toISOString(), secondsPerTransaction: 1, timeTravel: "evm_mine with a timestamp; no real-time waiting", approvalValiditySeconds: VALIDITY },
    contracts: { validatorRegistry: "contracts/src/ReleaseRegistryV2.sol ValidatorRegistry", policyRegistry: "contracts/src/ReleaseRegistryV2.sol PolicyRegistry",
      releaseRegistry: "contracts/src/ReleaseRegistryV3.sol ReleaseRegistryV3", compiler: `solc ${solc.version()} via contracts/scripts/compile.ts` },
    definitions: {
      resignatures: "PASS votes accepted in the rounds that made every live release VERIFIED again after the key event",
      blockedSeconds: "chain seconds (block timestamps) during which at least one live release was not VERIFIED; each transaction is its own block 1 s after the previous one, so this is a lower bound",
      servedVersions: "validator-set versions under which the live releases were VERIFIED again; versions passed without a re-approval are not served and cost no signatures",
      gatewayPinChangesPerCompany: "MCPSHIELD_VALIDATOR_SET_VERSION changes each company's Gateway needs, one per served version (apps/gateway/src/signed-admission.mjs:88)",
      "gas.scheduleRotationFirst": "a registry's first scheduleRotation, which fills its three empty pending slots; every chain here is fresh, so each scenario's scheduleRotation is a first one",
      "gas.scheduleRotationAfterRotation": "a later scheduleRotation on the same registry (gas step: after one rotate(), one key changed); rotate() leaves the pending slots filled",
      "gas.disableBySlot": "disable() compares validators[0], [1], [2] in order until it finds the key, so its gas grows with the key's slot",
      "gas.dailyRenewal": "gas step, second of two renewals: a new 1-day round on a release that is already VERIFIED, under the same set version, after A, B and C have all voted on this chain; the validator app caps every round at 24 h (apps/validator/src/v3.ts:21), so keeping a release VERIFIED takes one such round a day. The first PASS opens the round, the second decides it, the third is relayed after the decision",
      "gas.firstRenewalAfterDecision": "the third vote of the first renewal, C's first vote on this chain: it also writes C's nonce for the first time",
    },
    setup: s1.setup,
    scenarios: { S1: s1.result,
      S2: { title: "leaked key C: disable(C) at once, rotation to C' after the timelock",
        caughtBeforeUse: { assumption: "the leak is caught before C is used", withInterimReapproval: a, withoutInterimReapproval: b },
        caughtAfterQuarantine: { assumption: "before the leak is caught, C quarantines every live release for the longest TTL (1 day); disable(C) does not lift it and V3 has no call that does",
          withInterimReapproval: qa, withoutInterimReapproval: qb } },
      S3: s3 },
    gasStep: g,
    gas: { scheduleRotationFirst: stats([...runs.map((r) => r.gas.scheduleRotation), g.scheduleRotationFirst]),
      scheduleRotationAfterRotation: g.scheduleRotationAfterRotation, rotate: stats([...runs.map((r) => r.gas.rotate), g.rotate]),
      disable: stats([...[a, b, qa, qb].map((r) => r.gas.disable), ...s3.gas.disable, g.disableSlot0]),
      disableBySlot: { slot0: g.disableSlot0, slot1: s3.gas.disable[0], slot2: s3.gas.disable[1] },
      quarantine: merged([qa, qb].map((r) => r.quarantine!.gas)), policyPublish: g.policyPublish, policyDeprecate: g.policyDeprecate,
      dailyRenewal: { ...g.dailyRenewal, twoVotes: g.dailyRenewal.opensRound + g.dailyRenewal.decides,
        threeVotes: g.dailyRenewal.opensRound + g.dailyRenewal.decides + g.dailyRenewal.afterDecision },
      firstRenewalAfterDecision: g.firstRenewal.afterDecision,
      resignatureVote: merged(runs.map((r) => r.resignatureGas)) },
    assertedChecks: [...runs, g].reduce((sum, r) => sum + r.checks.length, 0),
  };
}

export type RotationRehearsalResult = Awaited<ReturnType<typeof runRotationRehearsal>>;
