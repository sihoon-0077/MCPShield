import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AdmissionView, BaselineNotice, ChainActionsView, PublisherEvidenceNotice, ReleaseWorkflow, VotesV3View, policyMatchesRelease, type Release, type Scan, type ChainAction, type Admission, type PublisherVerification, type V3Round, type V3Vote, type V3Votes } from "../components/release-workflow";

const release: Release = { releaseId: `0x${"1".repeat(64)}`, legacyReleaseId: "synthetic@1.0.0", toolId: "synthetic", version: "1.0.0", status: "UNVERIFIED", artifactDigest: `sha256:${"2".repeat(64)}`, toolSurfaceHash: `0x${"3".repeat(64)}`, policyHash: `0x${"4".repeat(64)}`, reportRoot: null, validUntil: null, chain: null };
const scan: Scan = { scanId: "synthetic-scan", releaseId: release.releaseId, policyHash: release.policyHash!, status: "COMPLETED", stage: "COMPLETED", attempts: 1, maxAttempts: 3, traceId: "5".repeat(32), createdAt: "2026-09-08T00:00:00Z", updatedAt: "2026-09-08T00:00:01Z", nextAttemptAt: "2026-09-08T00:00:00Z", result: { state: "READY_FOR_VALIDATORS", verdict: "ABSTAIN", scanResult: { scanStatus: "INCONCLUSIVE" } } };
const action: ChainAction = { actionId: "synthetic-action", releaseId: release.releaseId, kind: "ATTEST", status: "SUBMITTED", txHash: `0x${"6".repeat(64)}`, errorCode: null, chainId: 31337, registryAddress: `0x${"7".repeat(40)}`, createdAt: scan.createdAt, updatedAt: scan.updatedAt };
const publisherVerification: PublisherVerification = { status: "VERIFIED", purpose: "DEMO_ONLY_NOT_NPM_PROVENANCE", behaviorSafety: "NOT_ASSESSED", publisherId: "synthetic-publisher", sourceArtifactDigest: release.artifactDigest, publicKeyFingerprint: `sha256:${"9".repeat(64)}` };

test("publisher signature remains separate from FAIL, REVOKED and current admission for source and prepared releases", () => {
  for (const runtimeProfile of [undefined, "restricted-node-docker-v2"]) {
    const html = renderToStaticMarkup(<ReleaseWorkflow release={{ ...release, runtimeProfile, publisherVerification, status: "REVOKED" }} scans={[{ ...scan, result: { ...scan.result, verdict: "FAIL", scanResult: { scanStatus: "FAILED" } } }]} policies={[]} actions={[]} manage={false} onRefresh={async () => {}} />);
    for (const value of ["테스트 게시자 서명 확인됨", "행동 안전성은 별도 검사", "FAIL", "FAILED", "REVOKED", "직접 조회 필요", "테스트 전용 증거이며 npm provenance가 아닙니다", "브라우저가 서명을 독립 검증한 결과가 아닙니다", publisherVerification.publisherId!, publisherVerification.sourceArtifactDigest!, publisherVerification.publicKeyFingerprint!]) assert.ok(html.includes(value), value);
    assert.doesNotMatch(html, /API: ALLOW|type="password"/);
  }
});

test("missing, unconfigured and malformed publisher evidence never becomes a verified signature or exposes raw fields", () => {
  for (const proof of [undefined, null, {}, "VERIFIED", { ...publisherVerification, status: "NOT_CONFIGURED" }, { ...publisherVerification, status: "VALID" },
    { ...publisherVerification, purpose: "NPM_PROVENANCE" }, { ...publisherVerification, behaviorSafety: "SAFE" }, { ...publisherVerification, publisherId: "<script>unknown</script>" },
    { ...publisherVerification, sourceArtifactDigest: [release.artifactDigest] }, { ...publisherVerification, publicKeyFingerprint: undefined }]) {
    const html = renderToStaticMarkup(<PublisherEvidenceNotice release={{ ...release, publisherVerification: proof as PublisherVerification }} />);
    assert.match(html, /게시자 서명 미검증/); assert.match(html, /미확인/);
    assert.doesNotMatch(html, /테스트 게시자 서명 확인됨|검증한 원본의 공개 식별자|<script>|NPM_PROVENANCE|SAFE/);
  }
  const html = renderToStaticMarkup(<PublisherEvidenceNotice release={{ ...release, publisherVerification: { ...publisherVerification, privateKey: "SYNTHETIC_PRIVATE_KEY", manifestPath: "SYNTHETIC_PRIVATE_PATH", manifest: { signature: "SYNTHETIC_RAW_SIGNATURE" } } as PublisherVerification, chainUnavailable: true }} />);
  assert.match(html, /테스트 게시자 서명 확인됨/); assert.match(html, /현재 조회 불가/); assert.doesNotMatch(html, /SYNTHETIC_PRIVATE|SYNTHETIC_RAW/);
});

test("policy selection is bound to the release profile, not registry ordering", () => {
  const prepared = { policyHash: `0x${"a".repeat(64)}`, alias: "prepared-only", deprecatedAt: null, document: { profile: "restricted-node-docker-v1" } };
  const legacy = { policyHash: `0x${"b".repeat(64)}`, alias: "legacy-only", deprecatedAt: null, document: {} };
  assert.equal(policyMatchesRelease(release, prepared), false); assert.equal(policyMatchesRelease(release, legacy), true);
  assert.equal(policyMatchesRelease({ ...release, runtimeProfile: "restricted-node-docker-v1" }, prepared), true);
  assert.equal(policyMatchesRelease({ ...release, runtimeProfile: "restricted-node-docker-v1" }, legacy), false);
  const html = renderToStaticMarkup(<ReleaseWorkflow release={release} scans={[]} policies={[prepared, legacy]} actions={[]} manage={false} onRefresh={async () => {}} />);
  assert.match(html, /legacy-only/); assert.doesNotMatch(html, /prepared-only/);
});

test("baseline projection is selected-scan context, never a release approval or an inferred null", () => {
  const baselineId = `0x${"b".repeat(64)}`, previousId = `0x${"c".repeat(64)}`;
  const current = { ...scan, baselineReleaseId: baselineId, scanId: "current-baseline-scan", createdAt: "2026-10-01T00:00:00Z" };
  const html = renderToStaticMarkup(<ReleaseWorkflow release={{ ...release, runtimeProfile: "restricted-node-docker-v2", status: "VERIFIED", publisherVerification }} scans={[{ ...scan, baselineReleaseId: previousId }, current]} policies={[]} actions={[]} manage={false} onRefresh={async () => {}} />);
  assert.match(html, /선택한 검사의 비교 대상/); assert.match(html, new RegExp(baselineId)); assert.doesNotMatch(html, new RegExp(previousId));
  assert.match(html, /비교 선택은 해당 검사에만 적용/); assert.match(html, /이전 VERIFIED 상태·게시자 서명은 새 승인이 아니며/); assert.doesNotMatch(html, /API: ALLOW/);
  const without = renderToStaticMarkup(<BaselineNotice selection={{ baselineReleaseId: null }} label="선택한 검사의 비교 대상" />);
  assert.match(without, /비교하지 않음 · 이전 버전과의 변경 비교가 아닙니다/);
  for (const baselineReleaseId of [undefined, "", "null", "SYNTHETIC_PRIVATE_PATH", { privateKey: "SYNTHETIC_PRIVATE_KEY" }, [baselineId]]) {
    const unknown = renderToStaticMarkup(<BaselineNotice selection={{ baselineReleaseId: baselineReleaseId as string }} label="선택한 검사의 비교 대상" />);
    assert.match(unknown, /비교 대상 미제공 또는 확인 불가/); assert.doesNotMatch(unknown, /SYNTHETIC_PRIVATE|비교하지 않음 · 이전/);
  }
});

test("workflow renders real API stages without turning READY, submitted attestations or historical chain state into allow", () => {
  const html = renderToStaticMarkup(<ReleaseWorkflow release={release} scans={[scan]} policies={[{ policyHash: release.policyHash!, alias: "test", deprecatedAt: null }]} actions={[action, { ...action, actionId: "another" }, { ...action, actionId: "receipt-only", releaseId: null, kind: "ANCHOR_RECEIPTS" }]} manage={false} onRefresh={async () => {}} />);
  for (const value of ["READY", "ABSTAIN", "INCONCLUSIVE", "REPLAY 아님", "SUBMITTED", "영수증 대기", "quorum 아님", "체인 증빙 없음", "직접 조회 필요"]) assert.ok(html.includes(value), value);
  assert.doesNotMatch(html, /관리자 · 온체인 등록 요청|API: ALLOW|type="password"|ANCHOR_RECEIPTS|receipt-only/);
  const unavailable = { ...release, chainUnavailable: true, chain: { chainId: 31337, registryContract: action.registryAddress, observedBlock: 42, blockHash: `0x${"8".repeat(64)}`, txHash: action.txHash } };
  const admin = renderToStaticMarkup(<ReleaseWorkflow release={unavailable} scans={[scan]} policies={[]} actions={[]} manage onRefresh={async () => {}} />);
  assert.match(admin, /현재 조회 불가/); assert.match(admin, /이전 기록/); assert.match(admin, /온체인 등록 요청/); assert.match(admin, /type="checkbox" required=""/);
});

test("transaction preparation, receipt completion and expired/unsigned API responses stay explicitly distinct", () => {
  const html = renderToStaticMarkup(<ChainActionsView actions={["NEW", "PREPARED", "SUBMITTED", "COMPLETED", "FAILED"].map((status) => ({ ...action, status, actionId: status }))} />);
  for (const value of ["전송 대기", "전송 미확인", "영수증 대기", "최종성은 별도 확인", "실패"]) assert.ok(html.includes(value), value);
  const admission: Admission = { decision: "ALLOW", status: "VERIFIED", reasonCode: "RELEASE_VERIFIED", source: "EVM", releaseId: release.releaseId, policyHash: release.policyHash!, checkedAt: scan.createdAt, traceId: scan.traceId, signature: "synthetic-signature", snapshot: { expiresAt: scan.updatedAt, observedBlock: 42, blockHash: `0x${"8".repeat(64)}`, chainId: 31337, registryContract: action.registryAddress, operationClass: "READ_PRIVATE" } };
  const expired = renderToStaticMarkup(<AdmissionView admission={admission} now={Date.parse(scan.updatedAt) + 1} />);
  assert.match(expired, /스냅샷 만료/); assert.match(expired, /서명 검증·도구 실행은 하지 않으며/);
  const unsigned = renderToStaticMarkup(<AdmissionView admission={{ ...admission, decision: "BLOCK", source: "LOCAL_DEMO", snapshot: undefined, signature: undefined }} now={Date.now()} />);
  assert.match(unsigned, /온체인 증명 아님/); assert.match(unsigned, /서명된 스냅샷이 없습니다/);
});

test("chain retry exhaustion explains operator reconciliation without offering blind resubmission", () => {
  const html = renderToStaticMarkup(<ChainActionsView actions={[{ ...action, status: "DEAD_LETTER", attempts: 12,
    retryBudget: { maxAttempts: 12 }, nextAttemptAt: scan.updatedAt, errorCode: "RECEIPT_PENDING" }]} />);
  assert.match(html, /자동 재시도 중단 · 체인 확인 필요/);
  assert.match(html, /처리 시도 12회 \/ 최대 12회/);
  assert.match(html, /전송 결과가 불명확할 수 있습니다/);
  assert.doesNotMatch(html, /<button|다음 확인/);
  const pending = renderToStaticMarkup(<ChainActionsView actions={[{ ...action, attempts: 2, nextAttemptAt: scan.updatedAt }]} />);
  assert.match(pending, /처리 시도 2회/);
  assert.match(pending, /다음 확인/);
});

test("V3 votes show each validator's own verdict and evidence, dissent, late votes and split review without inventing approval", () => {
  const [a, b, c] = ["a", "b", "c"].map((digit) => `0x${digit.repeat(40)}`);
  const vote = (validator: string, verdict: "PASS" | "FAIL" | "ABSTAIN", extra: Partial<V3Vote> = {}): V3Vote => ({ validator, cast: true, verdict, evidenceHash: `0x${"e".repeat(64)}`,
    agreesWithOperator: true, afterDecision: false, txHash: `0x${"f".repeat(64)}`, evidence: { consistent: true, derivedVerdict: verdict, basis: verdict === "PASS" ? [] : ["CANARY_EXFILTRATION"], findings: [] }, ...extra });
  const round: V3Round = { roundId: `0x${"c".repeat(64)}`, scanId: scan.scanId, live: true, validFrom: 1793000000, validUntil: 1793086400, outcome: "APPROVED", approvals: 2, rejections: 0, abstentions: 1,
    openedAt: 1793000001, decidedAt: 1793000005, votes: [vote(a, "PASS"), vote(b, "PASS"), vote(c, "ABSTAIN", { agreesWithOperator: false, afterDecision: true, evidence: null })] };
  const view = (patch: Partial<V3Votes>): V3Votes => ({ registryVersion: 3, releaseId: release.releaseId, policyHash: release.policyHash!, registered: true, status: "VERIFIED", decisionRound: round.roundId, needsReview: false, rounds: [round], ...patch });
  const html = renderToStaticMarkup(<VotesV3View votes={view({})} operatorVerdicts={{ [scan.scanId]: "PASS" }} />);
  for (const value of ["승인 · 2/3 PASS 달성", "현재 판정 근거", "PASS 2 · FAIL 0 · 보류 1", "운영사 검사 권고: PASS", "운영사 검사와 다른 판정 · 그대로 기록", "결론 뒤에 들어온 표", "증거 파일 미제출 · 해시만 체인에 있음", "증거 파일과 판정 일치"]) assert.ok(html.includes(value), value);
  assert.equal(html.split("운영사 검사와 다른 판정").length - 1, 1, "only the ABSTAIN vote differs from a PASS recommendation");
  // An operator scan without a conclusion (no Docker sandbox) is a reference only: no vote is called a dissent against it.
  const inconclusive = renderToStaticMarkup(<VotesV3View votes={view({})} operatorVerdicts={{ [scan.scanId]: "ABSTAIN" }} />);
  assert.match(inconclusive, /결론이 없는 참고 값이라 표와 비교하지 않음/); assert.doesNotMatch(inconclusive, /운영사 검사와 다른 판정/);
  const split = renderToStaticMarkup(<VotesV3View votes={view({ status: "UNVERIFIED", needsReview: true, rounds: [{ ...round, outcome: "SPLIT", approvals: 1, rejections: 1, abstentions: 1 }] })} />);
  assert.match(split, /표가 갈림 · 사람 검토/); assert.match(split, /운영사가 결과를 덮어쓰지 않습니다/);
  assert.match(renderToStaticMarkup(<VotesV3View votes={view({ rounds: [] })} />), /운영사 검사 완료만으로는 승인되지 않습니다/);
  const quarantined = renderToStaticMarkup(<VotesV3View votes={view({ status: "REVOKED", quarantines: [{ validator: c, reason: "CANARY_EXFILTRATION", evidenceHash: `0x${"e".repeat(64)}`, expiresAt: 1793003600, txHash: `0x${"9".repeat(64)}` }],
    rounds: [{ ...round, outcome: "REJECTED", approvals: 0, rejections: 3, abstentions: 0, live: false, votes: [vote(a, "FAIL"), vote(b, "FAIL"), vote(c, "FAIL")] }] })} operatorVerdicts={{ [scan.scanId]: "FAIL" }} />);
  for (const value of ["긴급 격리 · 검증자", "사유 CANARY_EXFILTRATION", "운영사가 막을 수 없습니다", "폐기 · 2/3 FAIL 달성", "폐기 근거"]) assert.ok(quarantined.includes(value), value);
  assert.match(renderToStaticMarkup(<VotesV3View votes={null} error="조회 실패" />), /승인으로 간주하지 않습니다/);
  // A V3 release replaces the relay-job count with chain votes; the V2 wording stays for V2 releases (first workflow test).
  const v3Release: Release = { ...release, chain: { chainId: 31337, registryContract: action.registryAddress, registryVersion: 3, observedBlock: 7, blockHash: `0x${"d".repeat(64)}`, txHash: null } };
  const workflow = renderToStaticMarkup(<ReleaseWorkflow release={v3Release} scans={[scan]} policies={[]} actions={[]} manage={false} onRefresh={async () => {}} />);
  assert.match(workflow, /V3 운영 API · 검증자별 증거/); assert.match(workflow, /03 · 검증자 투표/); assert.match(workflow, /검증자 투표를 체인에서 불러오는 중입니다/);
  assert.doesNotMatch(workflow, /quorum 아님|API: ALLOW/);
});
