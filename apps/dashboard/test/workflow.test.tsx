import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AdmissionView, ChainActionsView, ReleaseWorkflow, policyMatchesRelease, type Release, type Scan, type ChainAction, type Admission } from "../components/release-workflow";

const release: Release = { releaseId: `0x${"1".repeat(64)}`, legacyReleaseId: "synthetic@1.0.0", toolId: "synthetic", version: "1.0.0", status: "UNVERIFIED", artifactDigest: `sha256:${"2".repeat(64)}`, toolSurfaceHash: `0x${"3".repeat(64)}`, policyHash: `0x${"4".repeat(64)}`, reportRoot: null, validUntil: null, chain: null };
const scan: Scan = { scanId: "synthetic-scan", releaseId: release.releaseId, policyHash: release.policyHash!, status: "COMPLETED", stage: "COMPLETED", attempts: 1, maxAttempts: 3, traceId: "5".repeat(32), createdAt: "2026-09-08T00:00:00Z", updatedAt: "2026-09-08T00:00:01Z", nextAttemptAt: "2026-09-08T00:00:00Z", result: { state: "READY_FOR_VALIDATORS", verdict: "ABSTAIN", scanResult: { scanStatus: "INCONCLUSIVE" } } };
const action: ChainAction = { actionId: "synthetic-action", releaseId: release.releaseId, kind: "ATTEST", status: "SUBMITTED", txHash: `0x${"6".repeat(64)}`, errorCode: null, chainId: 31337, registryAddress: `0x${"7".repeat(40)}`, createdAt: scan.createdAt, updatedAt: scan.updatedAt };

test("policy selection is bound to the release profile, not registry ordering", () => {
  const prepared = { policyHash: `0x${"a".repeat(64)}`, alias: "prepared-only", deprecatedAt: null, document: { profile: "restricted-node-docker-v1" } };
  const legacy = { policyHash: `0x${"b".repeat(64)}`, alias: "legacy-only", deprecatedAt: null, document: {} };
  assert.equal(policyMatchesRelease(release, prepared), false); assert.equal(policyMatchesRelease(release, legacy), true);
  assert.equal(policyMatchesRelease({ ...release, runtimeProfile: "restricted-node-docker-v1" }, prepared), true);
  assert.equal(policyMatchesRelease({ ...release, runtimeProfile: "restricted-node-docker-v1" }, legacy), false);
  const html = renderToStaticMarkup(<ReleaseWorkflow release={release} scans={[]} policies={[prepared, legacy]} actions={[]} manage={false} onRefresh={async () => {}} />);
  assert.match(html, /legacy-only/); assert.doesNotMatch(html, /prepared-only/);
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
