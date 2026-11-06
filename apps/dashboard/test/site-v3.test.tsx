import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { readdir, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { NextRequest } from "next/server";
import { GET } from "../app/api/control/[...path]/route";
import type { Admission, ChainAction, Release, Scan, V3Round, V3Vote, V3Votes } from "../components/release-workflow";
import { LANE_ROLE, chainLabel, chainState, consensusCard, eventText, findingsOf, flowView, groundsCard, laneOf, progressPhase, runHistory, severityCard, shownRound, txHref, verdictCard, when, witnessText, type HistoryItem } from "../components/site/v3-model";
import { FindingsPanel, RunsTable, V3FlowMap, VerdictCards } from "../components/site/v3-views";
import { startScan, votesPath, type Policy } from "../components/site/v3-api";

// Shaped after a seeded local run (demo:v3 --seed): validators in registry order A, B, C; C votes first and holds the emergency brake.
const A = "0xFFcf8FDEE72ac11b5c542428B35EEF5769C409f0", B = "0x22d491Bde2303f2f43325b2108D26f1eAbA1e32b", C = "0xE11BA2b4D45Eaed5996Cd0823791E0C93114882d";
const h = (digit: string) => `0x${digit.repeat(64)}`;
const NOW = Date.parse("2026-11-03T14:30:00.000Z"), sec = (ms: number) => Math.floor(ms / 1000);
const policyHash = h("0");
const chain = { chainId: 31337, registryContract: `0x${"c".repeat(40)}`, registryVersion: 3, observedBlock: 62, blockHash: h("b"), txHash: h("d") };
const release = (version: string, digit: string, status: string): Release => ({ releaseId: h(digit), legacyReleaseId: `mail-mcp@${version}`, toolId: h("4"), version, status,
  artifactDigest: `sha256:${digit.repeat(64)}`, toolSurfaceHash: h(digit), policyHash, reportRoot: h("5"), validUntil: "2026-11-04T14:04:06.000Z", chain });
const R100 = release("1.0.0", "a", "VERIFIED"), R101 = release("1.0.1", "f", "REVOKED");
const scan = (id: string, rel: Release, status: string, verdict = "ABSTAIN", updatedAt = new Date(NOW - 20_000).toISOString()): Scan => ({ scanId: id, releaseId: rel.releaseId, policyHash,
  status, stage: status === "COMPLETED" ? "DONE" : "SCAN", attempts: 1, maxAttempts: 3, traceId: "7".repeat(32), createdAt: new Date(NOW - 30_000).toISOString(), updatedAt, nextAttemptAt: updatedAt,
  result: status === "COMPLETED" ? { state: "READY_FOR_VALIDATORS", verdict, validUntil: "2026-11-04T14:04:06.000Z", scanResult: { scanStatus: verdict === "FAIL" ? "FAILED" : "INCONCLUSIVE" } } : undefined });
const SCAN100 = "11111111-2222-4333-8444-555555555555", SCAN101 = "66666666-7777-4888-9999-000000000000";
const BAD_FINDINGS = [{ code: "UNSAFE_MODULE_LOAD", severity: "HIGH", stage: "STATIC", deterministic: true }, { code: "SENSITIVE_FILE_READ", severity: "HIGH", stage: "STATIC", deterministic: true },
  { code: "UNDECLARED_EGRESS", severity: "HIGH", stage: "STATIC", deterministic: true }, { code: "SEMANTIC_BEHAVIOR_MISMATCH", severity: "HIGH", stage: "AI", deterministic: false },
  { code: "SENSITIVE_FILE_READ", severity: "HIGH", stage: "SANDBOX", deterministic: true }, { code: "UNDECLARED_EGRESS", severity: "HIGH", stage: "SANDBOX", deterministic: true },
  { code: "CANARY_EXFILTRATION", severity: "CRITICAL", stage: "SANDBOX", deterministic: true }];
const BASIS = ["UNSAFE_MODULE_LOAD", "SENSITIVE_FILE_READ", "UNDECLARED_EGRESS", "CANARY_EXFILTRATION"];
const cast = (validator: string, verdict: "PASS" | "FAIL" | "ABSTAIN", digit: string, extra: Partial<V3Vote> = {}, evidence: Partial<NonNullable<V3Vote["evidence"]>> = {}): V3Vote => ({
  validator, cast: true, verdict, evidenceHash: h(digit), agreesWithOperator: null, afterDecision: false, txHash: h(digit === "9" ? "8" : "9"),
  evidence: { consistent: true, derivedVerdict: verdict, basis: verdict === "FAIL" ? BASIS : [], findings: verdict === "FAIL" ? BAD_FINDINGS : [], ai: null, ...evidence }, ...extra });
const none = (validator: string): V3Vote => ({ validator, cast: false, verdict: null, evidenceHash: null, agreesWithOperator: null, afterDecision: null, txHash: null, evidence: null });
const round = (scanId: string, outcome: string, votes: V3Vote[], decidedAgoMs: number | null = 60_000): V3Round => ({ roundId: h(outcome === "REJECTED" ? "6" : "7"), scanId, live: outcome !== "REJECTED",
  validFrom: sec(NOW - 30_000), validUntil: sec(NOW + 86_000_000), outcome, approvals: votes.filter((v) => v.verdict === "PASS").length, rejections: votes.filter((v) => v.verdict === "FAIL").length,
  abstentions: votes.filter((v) => v.verdict === "ABSTAIN").length, openedAt: sec(NOW - 25_000), decidedAt: decidedAgoMs === null ? null : sec(NOW - decidedAgoMs), votes });
const votesOf = (rel: Release, rounds: V3Round[], extra: Partial<V3Votes> = {}): V3Votes => ({ registryVersion: 3, releaseId: rel.releaseId, policyHash, registered: true, status: rel.status,
  decisionRound: rounds[0]?.roundId ?? null, needsReview: false, quarantineUntil: null, validatorSetVersion: 1, validators: [A, B, C], rounds, quarantines: [], ...extra });
const admission = (decision: "ALLOW" | "BLOCK", status: string, reasonCode: string): Admission => ({ decision, status, reasonCode, releaseId: R100.releaseId, policyHash, source: "EVM",
  checkedAt: new Date(NOW).toISOString(), traceId: "8".repeat(32), snapshot: { expiresAt: new Date(NOW + 30_000).toISOString(), observedBlock: 70, blockHash: h("b"), chainId: 31337, registryContract: chain.registryContract, operationClass: "READ_PRIVATE" } });
const register = (rel: Release, status = "COMPLETED"): ChainAction => ({ actionId: h("3"), releaseId: rel.releaseId, kind: "REGISTER_RELEASE", status, txHash: h("2"), errorCode: null, chainId: 31337,
  registryAddress: chain.registryContract, createdAt: new Date(NOW - 60_000).toISOString(), updatedAt: new Date(NOW - 50_000).toISOString() });
const event = (eventName: string, payload: Record<string, unknown>): HistoryItem => ({ eventName, createdAt: new Date(NOW - 10_000).toISOString(), payload });
const text = (html: string) => html.replace(/<wbr\/?>/g, "").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");

// 1.0.0 re-approved: C and A pass first (2/3), B's PASS lands after the decision. 1.0.1 revoked: C quarantined, all three FAIL, B after the decision.
const APPROVED = round(SCAN100, "APPROVED", [cast(A, "PASS", "a"), cast(B, "PASS", "b", { afterDecision: true }), cast(C, "PASS", "c")]);
const VOTES100 = votesOf(R100, [APPROVED]);
const REJECTED = round(SCAN101, "REJECTED", [cast(A, "FAIL", "d"), cast(B, "FAIL", "e", { afterDecision: true }), cast(C, "FAIL", "9")]);
const VOTES101 = votesOf(R101, [REJECTED], { quarantineUntil: sec(NOW + 3_000_000), quarantines: [{ validator: C, reason: "CANARY_EXFILTRATION", evidenceHash: h("9"), expiresAt: sec(NOW + 3_000_000), txHash: h("1") }] });

test("chain labels come from chainId only: Ganache is never a testnet, Base Sepolia always is, and only Base Sepolia links out", () => {
  assert.equal(chainLabel(31337), "로컬 Ganache · chain 31337"); assert.doesNotMatch(chainLabel(31337), /테스트넷/);
  assert.equal(chainLabel(84532), "Base Sepolia 테스트넷 · chain 84532"); assert.doesNotMatch(chainLabel(84532), /아님/);
  assert.equal(chainLabel(1337), "chain 1337"); assert.equal(chainLabel(null), "체인 확인 전");
  assert.equal(txHref(31337, h("2")), null); assert.equal(txHref(84532, h("2")), `https://sepolia.basescan.org/tx/${h("2")}`); assert.equal(txHref(84532, "0x12"), null);
  const html = renderToStaticMarkup(<V3FlowMap flow={flowView({ release: R101, scan: scan(SCAN101, R101, "COMPLETED", "FAIL"), votes: VOTES101, round: REJECTED, actions: [register(R101)], admission: admission("BLOCK", "REVOKED", "RELEASE_REVOKED") })} />);
  assert.doesNotMatch(html, /basescan|테스트넷/, "a local Ganache run links nowhere and is not called a testnet");
});

test("lanes never claim done without data, and lanes follow registry order whatever the address case", () => {
  const open = round(SCAN100, "OPEN", [none(A), none(B), cast(C, "PASS", "c")], null);
  const history = [event("validator.round.announced", { scanId: SCAN100, validator: C.toLowerCase() }), event("validator.vote.received", { scanId: SCAN100, validator: C, verdict: "PASS" }),
    event("validator.round.announced", { scanId: SCAN100, validator: A })];
  for (const validators of [[A, B, C], [A, B, C].map((value) => value.toLowerCase()), [A, B, C].map((value) => value.toUpperCase().replace(/^0X/, "0x"))]) {
    const votes = votesOf(R100, [open], { validators }), flow = flowView({ release: R100, scan: scan(SCAN100, R100, "COMPLETED"), votes, round: open, history, actions: [register(R100)], admission: null });
    const [a, b, c] = flow.lanes;
    assert.deepEqual(flow.lanes.map((lane) => lane.lane), ["A", "B", "C"]);
    assert.equal(c.voteKey, "PASS"); assert.equal(c.rescan.state, "done"); assert.equal(c.signed.state, "done");
    assert.equal(a.voteKey, "NONE"); assert.equal(a.rescan.state, "running"); assert.equal(a.signed.state, "pending");
    assert.equal(b.voteKey, "NONE"); assert.equal(b.rescan.state, "pending"); assert.equal(b.signed.state, "pending"); assert.equal(b.witness.label, "투표 후 표시");
    const steps = Object.fromEntries(flow.steps.map((step) => [step.key, step]));
    assert.equal(steps.lanes.state, "running"); assert.equal(steps.decision.state, "running"); assert.equal(steps.gateway.state, "pending"); assert.equal(flow.gateway, null);
    assert.equal(laneOf(votes, C.toLowerCase()), "C"); assert.equal(laneOf(votes, B), "B");
    const html = renderToStaticMarkup(<V3FlowMap flow={flow} />);
    assert.match(html, /data-lane="C" data-vote="PASS"/); assert.match(html, /data-lane="A" data-vote="NONE"/); assert.match(html, /data-step="gateway" data-state="pending"/);
    assert.match(html, /data-decision="OPEN"/); assert.doesNotMatch(html, /data-state="done"[^>]*data-gateway/);
  }
  // A relay receipt without a chain vote is not a vote yet.
  const relayed = laneOfFlow(round(SCAN100, "OPEN", [none(A), none(B), none(C)], null), [event("validator.vote.received", { scanId: SCAN100, validator: C, verdict: "PASS" })]);
  assert.equal(relayed.signed.state, "running"); assert.equal(relayed.signed.title, "중계 접수 · 체인 기록 대기"); assert.equal(relayed.voteKey, "NONE");
});
function laneOfFlow(r: V3Round, history: HistoryItem[]) {
  return flowView({ release: R100, scan: scan(SCAN100, R100, "COMPLETED"), votes: votesOf(R100, [r]), round: r, history, actions: [register(R100)] }).lanes[2];
}

test("the AI witness is read from the validator's own evidence and is never shown as the one that decides", () => {
  assert.equal(witnessText(cast(A, "PASS", "a")).label, "없음 · 규칙·시험 환경만");
  const answered = witnessText(cast(A, "PASS", "a", {}, { ai: { model: "gpt-6-luna", status: "COMPLETED" } }));
  assert.equal(answered.model, "gpt-6-luna"); assert.equal(answered.label, "응답함 · 의심 없음"); assert.equal(answered.tone, "neutral", "an answering witness is never shown in the PASS colour");
  // A witness whose suspicion held a would-be PASS: amber, with the reason, still no authority.
  const suspicion = [{ code: "SEMANTIC_BEHAVIOR_MISMATCH", severity: "HIGH", stage: "AI", deterministic: false }];
  const held = witnessText(cast(A, "ABSTAIN", "a", {}, { basis: ["SEMANTIC_BEHAVIOR_MISMATCH"], findings: suspicion, ai: { model: "gpt-6-luna", status: "COMPLETED" } }));
  assert.equal(held.label, "응답함 · 의심 1건"); assert.equal(held.tone, "review"); assert.equal(held.note, "AI 의심 → PASS 대신 보류 (판정 권한 없음)");
  for (const vote of [cast(A, "PASS", "a"), cast(A, "FAIL", "a", {}, { ai: { model: "gpt-6-luna", status: "COMPLETED" } }), none(B)]) assert.notEqual(witnessText(vote).tone, "pass");
  const silent = witnessText(cast(C, "ABSTAIN", "c", {}, { basis: ["AI_UNAVAILABLE"], ai: { model: "gemini-3.5-flash", status: "UNAVAILABLE" } }));
  assert.equal(silent.label, "응답 없음"); assert.equal(silent.note, "PASS 대신 보류 (AI_UNAVAILABLE)"); assert.equal(silent.tone, "review");
  const legacy = cast(A, "PASS", "a"); delete legacy.evidence!.ai;
  assert.equal(witnessText(legacy).label, "확인 불가 · 이전 API 기록");
  assert.equal(witnessText({ ...cast(A, "PASS", "a"), evidence: null }).label, "확인 불가 · 증거 요약 없음");
  assert.equal(witnessText(none(B)).label, "투표 후 표시");
  const mixed = round(SCAN100, "SPLIT", [cast(A, "PASS", "a", {}, { ai: { model: "gpt-6-luna", status: "COMPLETED" } }), cast(B, "PASS", "b"),
    cast(C, "ABSTAIN", "c", {}, { basis: ["AI_UNAVAILABLE"], ai: { model: "gemini-3.5-flash", status: "UNAVAILABLE" } })]);
  const html = renderToStaticMarkup(<V3FlowMap flow={flowView({ release: R100, votes: votesOf(R100, [mixed], { status: "UNVERIFIED", needsReview: true }), round: mixed })} />);
  for (const value of ["gpt-6-luna", "응답함 · 의심 없음", "없음 · 규칙·시험 환경만", "gemini-3.5-flash", "응답 없음", "PASS 대신 보류 (AI_UNAVAILABLE)", "AI는 증인일 뿐입니다", "SINGLE_INSTITUTION_DEMO"]) assert.ok(text(html).includes(value), value);
  assert.doesNotMatch(text(html), /AI가 찾/);
});

test("a lane's role never claims an AI witness: the witness comes from that vote's own evidence, and the team-run roles are disclosed", () => {
  for (const role of Object.values(LANE_ROLE)) assert.doesNotMatch(role, /AI/);
  assert.match(LANE_ROLE.C, /긴급 격리/);
  const open = round(SCAN100, "OPEN", [none(A), none(B), none(C)], null);
  for (const compact of [false, true]) {
    const html = text(renderToStaticMarkup(<V3FlowMap compact={compact} flow={flowView({ release: R100, scan: scan(SCAN100, R100, "COMPLETED"), votes: votesOf(R100, [open]), round: open })} />));
    assert.doesNotMatch(html, /\+ AI 증인|AI 증인:|gpt|gemini/i, "before any vote nothing says a lane has an AI witness");
    assert.match(html, /SINGLE_INSTITUTION_DEMO/); assert.match(html, /팀이 운영/);
  }
});

test("1.0.0 re-approval: 2-of-3 PASS on chain, the late third vote is kept, and green needs an ALLOW from the API", () => {
  const base = { release: R100, scan: scan(SCAN100, R100, "COMPLETED"), votes: VOTES100, round: APPROVED, actions: [register(R100)] };
  const flow = flowView({ ...base, admission: admission("ALLOW", "VERIFIED", "RELEASE_VERIFIED") });
  const steps = Object.fromEntries(flow.steps.map((step) => [step.key, step]));
  assert.equal(steps.decision.title, "승인 · 2/3 PASS 달성"); assert.equal(steps.decision.state, "done"); assert.equal(flow.gateway, "ALLOW"); assert.equal(flow.done, 5);
  assert.ok(flow.lanes[1].signed.lines.includes("결론 뒤 기록 · 결과 불변"));
  assert.ok(steps.register.lines[0].startsWith("artifact sha256:aa"), "the registered artifact digest, shortened");
  assert.equal(verdictCard({ votes: VOTES100, release: R100, admission: admission("ALLOW", "VERIFIED", "RELEASE_VERIFIED") }).tone, "pass");
  assert.notEqual(verdictCard({ votes: VOTES100, release: R100, admission: null }).tone, "pass", "no admission lookup yet: not green");
  assert.notEqual(verdictCard({ votes: VOTES100, release: R100, admission: admission("BLOCK", "VERIFIED", "ATTESTATION_EXPIRED") }).tone, "pass");
  const pending = flowView({ ...base, admission: null });
  assert.notEqual(pending.steps[4].state, "done"); assert.equal(pending.gateway, null);
  const consensus = consensusCard(APPROVED);
  assert.equal(consensus.value, "3/3 PASS"); assert.equal(consensus.lines[0], "승인 · 2/3 PASS 달성 · 결론 뒤 1표 기록");
  assert.equal(severityCard(APPROVED, VOTES100).value, "없음"); assert.match(severityCard(APPROVED, VOTES100).lines[0], /검증자 A·B·C의 증거 요약 기준/); assert.equal(groundsCard(APPROVED).lines[0], "차단 근거 없음");
  const html = renderToStaticMarkup(<VerdictCards votes={VOTES100} release={R100} admission={admission("ALLOW", "VERIFIED", "RELEASE_VERIFIED")} round={APPROVED} />);
  assert.match(html, /data-final="VERIFIED"/); assert.match(html, /metric-card verdict allowed/); assert.match(text(html), /Gateway ALLOW · RELEASE_VERIFIED/);
});

test("1.0.1 revoked: permanent, C's own emergency quarantine, four deterministic grounds and the local semantic signal labelled as such", () => {
  const blocked = admission("BLOCK", "REVOKED", "RELEASE_REVOKED");
  const card = verdictCard({ votes: VOTES101, release: R101, admission: blocked });
  assert.equal(card.value, "REVOKED"); assert.match(card.lines[0], /영구/); assert.equal(card.tone, "fail");
  const flow = flowView({ release: R101, scan: scan(SCAN101, R101, "COMPLETED", "FAIL"), votes: VOTES101, round: REJECTED, actions: [register(R101)], admission: blocked });
  const c = flow.lanes[2];
  assert.equal(c.quarantine?.title, "긴급 격리 실행 · CANARY_EXFILTRATION"); assert.ok(c.quarantine?.lines.includes("폐기가 격리보다 우선"));
  assert.equal(flow.lanes[0].quarantine.title, "격리 안 함", "A and B did not quarantine (their votes are indexed)"); assert.equal(flow.lanes[1].quarantine.title, "격리 안 함");
  assert.equal(flow.steps[3].title, "폐기 · 2/3 FAIL 달성"); assert.equal(flow.gateway, "BLOCK");
  const grounds = groundsCard(REJECTED);
  assert.equal(grounds.value, "4건"); assert.deepEqual(grounds.lines, ["의심 신호 1건 · 승인·폐기 근거 아님", "로컬 의미 규칙 · AI 모델 아님"]);
  assert.equal(severityCard(REJECTED).value, "CRITICAL"); assert.equal(consensusCard(REJECTED).value, "3/3 FAIL");
  const html = text(renderToStaticMarkup(<><VerdictCards votes={VOTES101} release={R101} admission={blocked} round={REJECTED} /><V3FlowMap flow={flow} /></>));
  for (const value of ["폐기됨 · 영구 (같은 바이트 재등록 불가)", "긴급 격리 실행 · CANARY_EXFILTRATION", "FAIL 근거 4건", "BLOCK · RELEASE_REVOKED"]) assert.ok(html.includes(value), value);
  assert.doesNotMatch(html, /ALLOW/);
  assert.equal(shownRound(VOTES101)?.roundId, REJECTED.roundId, "the deciding (revoking) round is shown for a release");
});

test("a stage-AI finding is called AI only for a vote whose own witness answered; otherwise it is the local semantic rule", () => {
  // No lane has a witness (the local stack, and B by design): the scanner's local fallback hard-codes stage AI.
  const rows = findingsOf(REJECTED, VOTES101), semantic = rows.find((row) => row.code === "SEMANTIC_BEHAVIOR_MISMATCH")!;
  assert.equal(semantic.deterministic, false); assert.deepEqual(semantic.stages, ["로컬 의미 규칙 (AI 모델 아님)"]); assert.deepEqual(semantic.lanes, ["A", "B", "C"]);
  assert.deepEqual(rows.filter((row) => row.deterministic).map((row) => row.code), ["CANARY_EXFILTRATION", "SENSITIVE_FILE_READ", "UNDECLARED_EGRESS", "UNSAFE_MODULE_LOAD"]);
  const html = text(renderToStaticMarkup(<FindingsPanel round={REJECTED} votes={VOTES101} />));
  assert.doesNotMatch(html, /AI 증인|(^|[^가-힣A-Z_])AI ·/, "no finding is labelled AI when no witness answered");
  assert.match(html, /참고 SEMANTIC_BEHAVIOR_MISMATCH/); assert.match(html, /승인·폐기 근거 아님 · PASS를 보류로만 바꿈/); assert.match(html, /보고 검증자 A·B·C/);
  // A answered with its own model, B has rules only: the same code is AI for A and the local rule for B.
  const mixed = round(SCAN101, "REJECTED", [cast(A, "FAIL", "d", {}, { ai: { model: "gpt-6-luna", status: "COMPLETED" } }), cast(B, "FAIL", "e"), cast(C, "FAIL", "9")]);
  const both = findingsOf(mixed, VOTES101).find((row) => row.code === "SEMANTIC_BEHAVIOR_MISMATCH")!;
  assert.deepEqual(both.stages, ["AI 증인 · 참고", "로컬 의미 규칙 (AI 모델 아님)"]);
  assert.deepEqual(groundsCard(mixed).lines, ["의심 신호 1건 · 승인·폐기 근거 아님", "AI 증인 의심 포함 · PASS를 보류로만 바꿈"]);
});

test("a quarantine belongs to the round whose evidence backs it, and a lane says nothing about it before the indexer has seen its vote", () => {
  const quarantine = { validator: C, reason: "CANARY_EXFILTRATION", evidenceHash: h("9"), expiresAt: sec(NOW + 3_000_000), txHash: h("1") };
  // C's vote is on chain but its transaction is not indexed yet: neither "격리 안 함" nor a quarantine from another round.
  const unindexed = round(SCAN101, "OPEN", [none(A), none(B), cast(C, "FAIL", "c", { txHash: null })], null);
  let c = flowView({ release: R101, votes: votesOf(R101, [unindexed], { quarantines: [] }), round: unindexed }).lanes[2];
  assert.equal(c.quarantine.title, "격리 기록 확인 중"); assert.equal(c.quarantine.state, "running");
  // An older round's quarantine (its evidence backs C's vote there) is not shown on a later round.
  const later = round(SCAN100, "OPEN", [none(A), none(B), cast(C, "FAIL", "c")], null), earlier = { ...REJECTED, roundId: h("e") };
  c = flowView({ release: R101, votes: votesOf(R101, [later, earlier], { quarantines: [quarantine] }), round: later }).lanes[2];
  assert.equal(c.quarantine.title, "격리 안 함");
  // C quarantines first and votes after: until the vote lands the quarantine already shows on C's lane.
  const before = round(SCAN101, "OPEN", [none(A), none(B), none(C)], null);
  c = flowView({ release: R101, votes: votesOf(R101, [before], { quarantines: [quarantine] }), round: before }).lanes[2];
  assert.equal(c.quarantine.title, "긴급 격리 실행 · CANARY_EXFILTRATION");
  assert.match(verdictCard({ votes: votesOf(R100, [before], { status: "QUARANTINED", quarantineUntil: quarantine.expiresAt, quarantines: [] }), release: R100 }).lines[0], /검증자 확인 중/);
});

test("before the indexer reaches a vote, the operator's completed relay names its transaction, and only the registry's quarantine record says 격리 안 함", () => {
  // Base Sepolia: the indexer lags by hours while the outbox already holds a status-1 receipt for each relayed vote, and the API reads
  // each vote's VoteRecorded log (afterDecision) from that receipt.
  const relayed = (validator: string, digit: string, afterDecision: boolean | null = false) => cast(validator, "PASS", digit, { txHash: h("2"), txSource: "OPERATOR_RELAY", afterDecision });
  const live = round(SCAN100, "APPROVED", [relayed(A, "a"), relayed(B, "b", true), relayed(C, "c")], 5_000);
  const never = { [A.toLowerCase()]: 0, [B.toLowerCase()]: 0, [C.toLowerCase()]: 0 };
  let lanes = flowView({ release: R100, votes: votesOf(R100, [live], { quarantineUsedAt: never }), round: live }).lanes;
  for (const lane of lanes) {
    assert.equal(lane.signed.tx?.hash, h("2")); assert.equal(lane.signed.tx?.label, "중계", "the hash says where it came from");
    assert.ok(!lane.signed.lines.includes("거래 해시 확인 중")); assert.equal(lane.quarantine.title, "격리 안 함", "the registry says it never quarantined this release");
  }
  // The flow map names the source once, under the lanes, without adding a line to any cell (the progress screen fits 1600x900).
  const map = text(renderToStaticMarkup(<V3FlowMap flow={flowView({ release: R100, votes: votesOf(R100, [live], { quarantineUsedAt: never }), round: live })} />));
  assert.match(map, /중계 0x22222222…2222/); assert.match(map, /중계로 표시된 해시는 인덱서가 읽기 전, 운영사가 보낸 그 표의 거래를 성공 영수증으로 확인한 것입니다/);
  // C has used its one quarantine on this release and nothing is indexed: the lane does not claim either way.
  lanes = flowView({ release: R100, votes: votesOf(R100, [live], { quarantineUsedAt: { ...never, [C.toLowerCase()]: sec(NOW - 90_000) } }), round: live }).lanes;
  assert.equal(lanes[2].quarantine.title, "격리 기록 확인 중"); assert.equal(lanes[0].quarantine.title, "격리 안 함");
  // An API that does not report the registry read: a relay hash alone never becomes "격리 안 함".
  lanes = flowView({ release: R100, votes: votesOf(R100, [live]), round: live }).lanes;
  assert.ok(lanes.every((lane) => lane.quarantine.title === "격리 기록 확인 중"));
  // An indexed hash keeps the old meaning and carries no relay note.
  const indexed = flowView({ release: R100, votes: votesOf(R100, [APPROVED]), round: APPROVED });
  assert.ok(indexed.lanes.every((lane) => lane.signed.tx?.label === undefined && lane.quarantine.title === "격리 안 함"));
  assert.doesNotMatch(text(renderToStaticMarkup(<V3FlowMap flow={indexed} />)), /중계 0x|중계로 표시된/);
  assert.ok(lanes.length === 3 && flowView({ release: R100, votes: votesOf(R100, [live], { quarantineUsedAt: never }), round: live }).lanes[1].signed.lines.includes("결론 뒤 기록 · 결과 불변"),
    "the late vote says so from the relay receipt, before the indexer");
  // The progress screen does not wait out the 45 s grace once every cast vote has a transaction and a known afterDecision; a vote
  // whose afterDecision is still unknown keeps it waiting (at most 45 s), so the late-vote note is not lost.
  const allow = admission("ALLOW", "VERIFIED", "RELEASE_VERIFIED"), completed = scan(SCAN100, R100, "COMPLETED");
  assert.equal(progressPhase({ scanId: SCAN100, scan: completed, votes: votesOf(R100, [live], { quarantineUsedAt: never }), round: live, admission: allow, now: NOW }), "done");
  const unknown = round(SCAN100, "APPROVED", [relayed(A, "a"), relayed(B, "b", null), relayed(C, "c")], 5_000);
  assert.equal(progressPhase({ scanId: SCAN100, scan: completed, votes: votesOf(R100, [unknown]), round: unknown, admission: allow, now: NOW }), "decided");
  assert.equal(progressPhase({ scanId: SCAN100, scan: completed, votes: votesOf(R100, [unknown]), round: unknown, admission: allow, now: NOW + 60_000 }), "done");
});

test("격리 안 함 needs the registry: an indexed vote whose validator used its quarantine with other evidence shows that quarantine", () => {
  // C quarantined with evidence E1 (h("9")), its first vote never landed, and after a restart its vote landed with new evidence E2.
  const quarantine = { validator: C, reason: "CANARY_EXFILTRATION", evidenceHash: h("9"), expiresAt: sec(NOW + 3_000_000), txHash: h("1") };
  const live = round(SCAN101, "OPEN", [none(A), none(B), cast(C, "FAIL", "c", { txSource: "INDEXER" })], null);
  const usedC = { [A.toLowerCase()]: 0, [B.toLowerCase()]: 0, [C.toLowerCase()]: sec(NOW - 60_000) };
  let c = flowView({ release: R101, votes: votesOf(R101, [live], { quarantines: [quarantine], quarantineUsedAt: usedC }), round: live }).lanes[2];
  assert.equal(c.quarantine.title, "긴급 격리 기록 · CANARY_EXFILTRATION"); assert.ok(c.quarantine.lines.includes("이 표와 다른 증거로 기록됨"));
  assert.equal(c.quarantine.tx?.hash, h("1"));
  // The same quarantine tied by evidence to C's vote in an earlier round: this round's lane says 격리 안 함.
  const earlier = { ...REJECTED, roundId: h("e") };
  c = flowView({ release: R101, votes: votesOf(R101, [live, earlier], { quarantines: [quarantine], quarantineUsedAt: usedC }), round: live }).lanes[2];
  assert.equal(c.quarantine.title, "격리 안 함");
  // Used, but not indexed yet: no claim either way.
  c = flowView({ release: R101, votes: votesOf(R101, [live], { quarantines: [], quarantineUsedAt: usedC }), round: live }).lanes[2];
  assert.equal(c.quarantine.title, "격리 기록 확인 중");
  // A 0 read from a lagging RPC backend never hides an indexed quarantine that no other round accounts for.
  c = flowView({ release: R101, votes: votesOf(R101, [live], { quarantines: [quarantine], quarantineUsedAt: { ...usedC, [C.toLowerCase()]: 0 } }), round: live }).lanes[2];
  assert.equal(c.quarantine.title, "긴급 격리 기록 · CANARY_EXFILTRATION");
});

test("a failed chain read never becomes a state: no database fallback, no UNVERIFIED, no approval", () => {
  assert.deepEqual(chainState({ votes: undefined, release: R100, error: "운영 API에 연결할 수 없습니다 (503)." }), { status: null, text: "체인 조회 실패 · 상태 미확인 (승인으로 간주하지 않음)", failed: true });
  assert.equal(chainState({ votes: { ...VOTES100, status: undefined, registered: true, rounds: [] }, release: { ...R100, status: "UNVERIFIED", chainUnavailable: true } }).status, null);
  assert.match(chainState({ votes: { ...VOTES100, status: undefined, registered: true, rounds: [] }, release: { ...R100, chainUnavailable: true } }).text, /체인 조회 불가/);
  assert.equal(chainState({ votes: { ...VOTES100, status: undefined, registered: false, rounds: [] }, release: R100 }).text, "체인에 미등록");
  assert.equal(chainState({ votes: VOTES101, release: { ...R101, status: "VERIFIED" } }).status, "REVOKED", "the chain view wins over the database copy");
  const card = verdictCard({ votes: undefined, release: R100, admission: null, votesError: "조회 실패" });
  assert.equal(card.value, "—"); assert.notEqual(card.tone, "pass"); assert.match(card.lines[0], /체인 조회 실패/);
  assert.equal(flowView({ release: R100, votes: undefined, votesError: "조회 실패" }).status, null);

});

test("split and quarantined releases are never green and never produce an ALLOW", () => {
  const split = round(SCAN100, "SPLIT", [cast(A, "PASS", "a"), cast(B, "FAIL", "b"), cast(C, "ABSTAIN", "c", {}, { basis: ["SEMANTIC_BEHAVIOR_MISMATCH"] })]);
  const quarantined = votesOf(R100, [round(SCAN100, "OPEN", [none(A), none(B), none(C)], null)], { status: "QUARANTINED", quarantineUntil: sec(NOW + 3600),
    quarantines: [{ validator: C, reason: "CANARY_EXFILTRATION", evidenceHash: h("9"), expiresAt: sec(NOW + 3600), txHash: h("1") }] });
  for (const [votes, r, reason] of [[votesOf(R100, [split], { status: "UNVERIFIED", needsReview: true }), split, "RELEASE_UNVERIFIED"], [quarantined, quarantined.rounds[0], "RELEASE_QUARANTINED"]] as const) {
    const blocked = admission("BLOCK", votes.status!, reason);
    const card = verdictCard({ votes, release: R100, admission: blocked });
    assert.notEqual(card.tone, "pass");
    const html = text(renderToStaticMarkup(<><VerdictCards votes={votes} release={R100} admission={blocked} round={r} /><V3FlowMap flow={flowView({ release: R100, votes, round: r, admission: blocked })} /></>));
    assert.doesNotMatch(html, /ALLOW/);
  }
  assert.match(verdictCard({ votes: votesOf(R100, [split], { status: "UNVERIFIED", needsReview: true }), release: R100 }).lines[0], /사람 검토/);
  assert.match(verdictCard({ votes: quarantined, release: R100 }).lines[0], /긴급 격리 중 .* 검증자 C/);
});

test("progress phases follow the data: operator, validators, decided, done, terminal, stalled", () => {
  const completed = scan(SCAN100, R100, "COMPLETED"), allow = admission("ALLOW", "VERIFIED", "RELEASE_VERIFIED");
  const twoOfThree = round(SCAN100, "APPROVED", [cast(A, "PASS", "a"), none(B), cast(C, "PASS", "c")], 10_000);
  assert.equal(progressPhase({ scanId: null }), "none");
  assert.equal(progressPhase({ scanId: SCAN100, signedOut: true }), "login");
  assert.equal(progressPhase({ scanId: SCAN100, notFound: true }), "missing", "an unknown scan ID is not a failed scan");
  assert.equal(progressPhase({ scanId: SCAN100, failed: true, scan: null }), "error", "an unreachable API before the first read is shown, not left loading");
  assert.equal(progressPhase({ scanId: SCAN100, scan: null }), "loading");
  assert.equal(progressPhase({ scanId: SCAN100, scan: scan(SCAN100, R100, "RUNNING"), now: NOW }), "operator");
  assert.equal(progressPhase({ scanId: SCAN100, scan: scan(SCAN100, R100, "DEAD_LETTER"), now: NOW }), "error");
  assert.equal(progressPhase({ scanId: SCAN100, scan: completed, votes: votesOf(R100, []), now: NOW }), "validators");
  assert.equal(progressPhase({ scanId: SCAN100, scan: completed, votes: VOTES100, round: round(SCAN100, "OPEN", [none(A), none(B), cast(C, "PASS", "c")], null), now: NOW }), "validators");
  assert.equal(progressPhase({ scanId: SCAN100, scan: completed, votes: VOTES100, round: twoOfThree, admission: allow, now: NOW }), "decided", "two votes, decided 10 s ago");
  assert.equal(progressPhase({ scanId: SCAN100, scan: completed, votes: VOTES100, round: APPROVED, admission: null, now: NOW }), "decided", "no admission lookup yet");
  assert.equal(progressPhase({ scanId: SCAN100, scan: completed, votes: VOTES100, round: APPROVED, admission: allow, admissionPending: true, now: NOW }), "decided");
  assert.equal(progressPhase({ scanId: SCAN100, scan: completed, votes: VOTES100, round: APPROVED, admission: allow, now: NOW }), "done");
  assert.equal(progressPhase({ scanId: SCAN100, scan: completed, votes: VOTES100, round: twoOfThree, admission: allow, now: NOW + 60_000 }), "done", "the third vote is not waited for forever");
  const unindexed = round(SCAN100, "APPROVED", [cast(A, "PASS", "a"), cast(B, "PASS", "b", { afterDecision: null, txHash: null }), cast(C, "PASS", "c")], 5_000);
  assert.equal(progressPhase({ scanId: SCAN100, scan: completed, votes: VOTES100, round: unindexed, admission: allow, now: NOW }), "decided", "a cast vote the indexer has not seen yet");
  assert.equal(progressPhase({ scanId: SCAN100, scan: completed, votes: VOTES100, round: unindexed, admission: allow, now: NOW + 60_000 }), "done");
  assert.equal(progressPhase({ scanId: SCAN101, scan: scan(SCAN101, R101, "COMPLETED", "FAIL"), votes: VOTES101, now: NOW }), "terminal");
  assert.equal(progressPhase({ scanId: SCAN100, scan: scan(SCAN100, R100, "COMPLETED", "ABSTAIN", new Date(NOW - 200_000).toISOString()), votes: votesOf(R100, []), now: NOW }), "stalled");
});

type Call = { path: string; body: unknown; method: string; key?: string };
function fakeApi(answer: (path: string, calls: Call[]) => unknown) {
  const calls: Call[] = [];
  const api = (async (path: string, body?: unknown, method?: string, key?: string) => {
    calls.push({ path, body, method: method ?? (body === undefined ? "GET" : "POST"), key });
    const value = answer(path, calls);
    if (value instanceof Error) throw value;
    return value;
  }) as Parameters<typeof startScan>[1]["api"];
  return { api, calls };
}
const POLICIES: Policy[] = [{ policyHash: h("1"), alias: "mvp-default-v1", version: "1.0.0", document: {}, createdAt: "2026-11-01T00:00:00Z", deprecatedAt: "2026-11-02T00:00:00Z" },
  { policyHash, alias: "mvp-default-v1", version: "1.0.0", document: {}, createdAt: "2026-11-01T00:00:00Z", deprecatedAt: null }];
const ADMIN = { read: true, scan: true, evidence: true, manage: true }, OPERATOR = { ...ADMIN, manage: false };

test("startScan registers only when the chain does not have the release, never opens a scan for a revoked one, and reuses one attempt key", async () => {
  const deps = (api: Parameters<typeof startScan>[1]["api"], capabilities = ADMIN) => ({ api, capabilities, policies: POLICIES, attemptKey: "attempt-1", onPhase: () => {}, sleep: async () => {} });
  const scanned = (reusedResult = false) => ({ scan: { scanId: SCAN100 }, reusedResult });
  // Registered already: no register call; the active default policy and the click's own key go with the scan request.
  let fake = fakeApi((path) => path === "releases/resolve" ? { release: R100 } : path.includes("/votes") ? VOTES100 : path === "scans" ? scanned() : new Error(path));
  assert.deepEqual(await startScan("1.0.0", deps(fake.api)), { kind: "scan", scanId: SCAN100, reused: false });
  assert.deepEqual(fake.calls.map((call) => call.path), ["releases/resolve", `releases/${R100.releaseId}/votes?policyHash=${policyHash}`, "scans"], "the vote view is read under the policy the scan will use");
  assert.deepEqual(fake.calls[0].body, { sourceType: "fixture", locator: "mail-mcp-1.0.0" });
  assert.deepEqual(fake.calls[2].body, { releaseId: R100.releaseId, policyHash }); assert.equal(fake.calls[2].key, "attempt-1");
  // Not on chain + admin: register, wait for the action to complete, then scan.
  let polls = 0;
  fake = fakeApi((path) => path === "releases/resolve" ? { release: { ...R100, status: "UNVERIFIED" } } : path.includes("/votes") ? { ...VOTES100, registered: false, status: undefined, rounds: [] }
    : path.endsWith("/register") ? { action: register(R100, "NEW") } : path.startsWith("chain/actions/") ? { action: register(R100, ++polls < 2 ? "SUBMITTED" : "COMPLETED") }
    : path === "scans" ? scanned(true) : new Error(path));
  const phases: string[] = [];
  assert.deepEqual(await startScan("1.0.0", { ...deps(fake.api), onPhase: (phase) => phases.push(phase) }), { kind: "scan", scanId: SCAN100, reused: true });
  assert.deepEqual(fake.calls.map((call) => call.path.replace(/0x[0-9a-f]+/g, "ID")), ["releases/resolve", "releases/ID/votes?policyHash=ID", "releases/ID/register", "chain/actions/ID", "chain/actions/ID", "scans"]);
  assert.deepEqual(phases, ["resolving", "registering", "requesting"]); assert.equal(fake.calls.at(-1)!.key, "attempt-1");
  // Not on chain + operator: refused before any register call.
  fake = fakeApi((path) => path === "releases/resolve" ? { release: R100 } : path.includes("/votes") ? { ...VOTES100, registered: false, rounds: [] } : new Error(path));
  await assert.rejects(startScan("1.0.0", deps(fake.api, OPERATOR)), /관리자 토큰이 필요합니다/);
  assert.equal(fake.calls.filter((call) => call.path.endsWith("/register")).length, 0);
  // Revoked: the evidence screen, never a new scan.
  fake = fakeApi((path) => path === "releases/resolve" ? { release: R101 } : path.includes("/votes") ? VOTES101 : new Error(path));
  assert.deepEqual(await startScan("1.0.1", deps(fake.api)), { kind: "revoked", releaseId: R101.releaseId });
  assert.equal(fake.calls.filter((call) => call.path === "scans").length, 0);
  // A failed registration and a missing default policy stop with a message.
  fake = fakeApi((path) => path === "releases/resolve" ? { release: R100 } : path.includes("/votes") ? { ...VOTES100, registered: false, rounds: [] }
    : path.endsWith("/register") ? { action: { ...register(R100, "DEAD_LETTER"), errorCode: "CHAIN_REVERTED" } } : new Error(path));
  await assert.rejects(startScan("1.0.0", deps(fake.api)), /온체인 등록 실패 · CHAIN_REVERTED/);
  await assert.rejects(startScan("1.0.0", { ...deps(fakeApi(() => new Error("unused")).api), policies: [POLICIES[0]] }), /기본 정책\(mvp-default-v1\)을 찾지 못했습니다/);
});

test("history rows come from operator scans with each scan's own round", () => {
  const html = renderToStaticMarkup(<RunsTable board={{ scans: [scan(SCAN101, R101, "COMPLETED", "FAIL"), scan(SCAN100, R100, "COMPLETED")], releases: [R100, R101], votes: { [R100.releaseId]: VOTES100, [R101.releaseId]: VOTES101 } }} />);
  assert.equal((html.match(/data-scan-row/g) ?? []).length, 2);
  for (const value of [`/scan-results?scan=${SCAN100}`, `/scan-results?scan=${SCAN101}`, "COMPLETED · 권고 FAIL", "A 불합격", "A 통과", "폐기", "승인", "mail-mcp"]) assert.ok(html.includes(value), value);
  assert.doesNotMatch(html, /실패/, "a FAIL vote is 불합격; 실패 is kept for errors");
  // The tool name comes from the release, never a fixed "mail-mcp".
  const other = { ...R100, releaseId: h("9"), legacyReleaseId: "weather-mcp@2.0.0", version: "2.0.0" };
  const row = renderToStaticMarkup(<RunsTable board={{ scans: [scan(SCAN100, other, "COMPLETED")], releases: [other], votes: {} }} />);
  assert.match(row, /weather-mcp/); assert.doesNotMatch(row, /mail-mcp/);
});

test("the progress history keeps this scan's and this round's records and only counts internal bookkeeping", () => {
  const items: HistoryItem[] = [event("validator.vote.received", { scanId: SCAN100, roundId: APPROVED.roundId, validator: C, verdict: "PASS" }),
    event("validator.vote.received", { scanId: SCAN101, roundId: REJECTED.roundId, validator: C, verdict: "FAIL" }),
    event("chain.VoteRecorded", { roundId: APPROVED.roundId.toUpperCase().replace(/^0X/, "0x"), validator: A }), event("chain.VoteRecorded", { roundId: REJECTED.roundId, validator: A }),
    event("chain.action.retry_scheduled", { actionId: h("3") }), event("scan.state.changed", { scanId: SCAN100 }), { ...event("scan.queued", { scanId: SCAN100 }), createdAt: new Date(NOW - 60_000).toISOString() }];
  const mine = runHistory(items, { since: new Date(NOW - 30_000).toISOString(), scanId: SCAN100, roundId: APPROVED.roundId });
  assert.deepEqual(mine.map((item) => item.eventName), ["validator.vote.received", "chain.VoteRecorded", "chain.action.retry_scheduled", "scan.state.changed"]);
  assert.equal(eventText(items[4], VOTES100), null); assert.equal(eventText(items[5], VOTES100), null);
  assert.equal(eventText(items[2], VOTES100), "체인 기록 · 검증자 A 표");
});

test("times read as one unit, and the vote view goes to the proxy with the exact policy only", async () => {
  assert.equal(when(new Date(2026, 10, 3, 23, 51).getTime() / 1000), "11.03\u00a023:51");
  assert.equal(votesPath(h("a"), policyHash), `releases/${h("a")}/votes?policyHash=${policyHash}`);
  assert.equal(votesPath(h("a"), "mvp-default-v1"), `releases/${h("a")}/votes`); assert.equal(votesPath(h("a"), undefined), `releases/${h("a")}/votes`);
  const token = "synthetic-site-v3-proxy-token", calls: string[] = [];
  const backend = createServer((request, response) => { calls.push(request.url ?? ""); response.setHeader("content-type", "application/json"); response.end('{"items":[]}'); });
  await new Promise<void>((done) => backend.listen(0, "127.0.0.1", done));
  const saved = { api: process.env.MCPSHIELD_API_URL, origin: process.env.MCPSHIELD_PUBLIC_ORIGIN };
  process.env.MCPSHIELD_API_URL = `http://127.0.0.1:${(backend.address() as { port: number }).port}`; process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  const context = (...path: string[]) => ({ params: Promise.resolve({ path }) }), headers = { cookie: `mcpshield_control=${token}` }, id = h("a");
  try {
    for (const [url, path] of [[`releases/${id}/votes?policyHash=${policyHash}`, ["releases", id, "votes"]], [`releases/${id}/votes?policyHash=${policyHash}0`, ["releases", id, "votes"]],
      [`releases?policyHash=${policyHash}`, ["releases"]]] as const) assert.equal((await GET(new NextRequest(`https://console.test/api/control/${url}`, { headers }), context(...path))).status, 200);
    assert.deepEqual(calls, [`/v1/releases/${id}/votes?policyHash=${policyHash}`, `/v1/releases/${id}/votes`, "/v1/releases"]);
  } finally {
    for (const [key, value] of [["MCPSHIELD_API_URL", saved.api], ["MCPSHIELD_PUBLIC_ORIGIN", saved.origin]] as const) if (value === undefined) delete process.env[key]; else process.env[key] = value;
    await new Promise((done) => backend.close(done));
  }
});

const FORBIDDEN = ["/api/judge", "Minjun", "LOCAL_DEMO", "테스트넷 아님", "not a testnet", "hello@mcpshield.ai", "© 2025", "Executed in Gateway", "Gateway 실행됨", "실행되었습니다",
  "42.8s", "96.4%", "24 modules", "filesystem-mcp", "mockSnapshot", "Sample Demo", "샘플 검사", "Developer workspace", "AI 위험 분석", "+ AI 증인", "fonts.googleapis.com"];
async function files(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  return (await Promise.all(entries.map((entry) => entry.isDirectory() ? files(join(dir, entry.name)) : [join(dir, entry.name)]))).flat();
}

test("no judge-demo leftovers, mock data, personal names or ledger mislabels in the product site sources", async () => {
  const root = resolve(import.meta.dirname, "..");
  const sources = [...await files(join(root, "components/site")), ...await files(join(root, "app/(site)"))];
  assert.ok(sources.length >= 15, "site sources found");
  for (const file of sources) {
    const content = await readFile(file, "utf8");
    for (const word of FORBIDDEN) assert.ok(!content.includes(word), `${word} in ${file}`);
  }
  const landing = await readFile(join(root, "components/site/landing.tsx"), "utf8");
  assert.ok(landing.includes("https://github.com/sihoon-0077/MCPShield")); assert.ok(landing.includes("© 2026"));
  assert.ok(!sources.some((file) => /scan-session\.ts$|backend-text\.ts$/.test(file)), "the judge client is gone");
});
