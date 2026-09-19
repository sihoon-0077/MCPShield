import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AppealRecords, linkedAppealScan, type Appeal } from "../components/appeal-records";
import { ScanRequestForm, scanPolicyAllowed, type ScanPolicy } from "../components/scan-request-form";
import type { Release, Scan } from "../components/release-workflow";

const release: Release = { releaseId: `0x${"1".repeat(64)}`, legacyReleaseId: "synthetic@1.0.0", toolId: "synthetic", version: "1.0.0", status: "REVOKED", artifactDigest: `sha256:${"2".repeat(64)}`, toolSurfaceHash: `0x${"3".repeat(64)}`, policyHash: `0x${"4".repeat(64)}`, reportRoot: `0x${"5".repeat(64)}`, validUntil: null, chain: null };
const policy: ScanPolicy = { policyHash: release.policyHash!, alias: "original-policy", deprecatedAt: null, document: {} };
const changed = { ...release, releaseId: `0x${"a".repeat(64)}`, artifactDigest: `sha256:${"a".repeat(64)}`, legacyReleaseId: "synthetic@1.0.1" };
const appeal: Appeal = { appealId: "synthetic-appeal", releaseId: release.releaseId, reason: "Synthetic immutable appeal", status: "OPEN", createdAt: "2026-09-19T00:00:00Z", original: { artifactDigest: release.artifactDigest, policyHash: release.policyHash, reportRoot: release.reportRoot } };
const scope = { appealId: appeal.appealId, toolId: release.toolId, artifactDigest: release.artifactDigest, policyHash: release.policyHash };

test("appeal scan choices require a different digest or pinned policy and the same tool/profile", () => {
  const newPolicy = { ...policy, policyHash: `0x${"b".repeat(64)}`, alias: "changed-policy" };
  assert.equal(scanPolicyAllowed(release, policy), true);
  assert.equal(scanPolicyAllowed(release, policy, scope), false);
  assert.equal(scanPolicyAllowed({ ...release, releaseId: changed.releaseId }, policy, scope), false, "new ID alone is insufficient");
  assert.equal(scanPolicyAllowed(changed, policy, scope), true);
  assert.equal(scanPolicyAllowed(release, newPolicy, scope), true);
  assert.equal(scanPolicyAllowed(release, newPolicy, { ...scope, policyHash: null }), false, "unknown original policy is not inferred");
  assert.equal(scanPolicyAllowed(changed, policy, { ...scope, policyHash: null }), true);
  for (const target of [undefined, { ...changed, toolId: "other-tool" }, { ...changed, runtimeProfile: "restricted-node-docker-v1" }]) assert.equal(scanPolicyAllowed(target, policy, scope), false);
  assert.equal(scanPolicyAllowed(changed, { ...policy, deprecatedAt: appeal.createdAt }, scope), false);
  const html = renderToStaticMarkup(<ScanRequestForm releases={[release, changed, { ...changed, releaseId: "other", toolId: "other-tool" }]} policies={[policy]} appeal={scope} onRefresh={async () => {}} />);
  assert.match(html, /method="post"/); assert.match(html, /synthetic@1.0.1/); assert.doesNotMatch(html, /synthetic@1.0.0|value="other"/);
  assert.match(html, /기존 결과 캐시를 재사용하지 않으며 원본 판정은 유지/); assert.match(html, /현재 화면의 재시도 식별키를 유지/);
});

test("appeal records gate rescan controls by role/state and only show fully bound linked scan evidence", () => {
  const props = { appeals: [appeal], releases: [release, changed], policies: [policy], manage: false, operator: true, onRefresh: async () => {} };
  const render = (overrides = {}) => renderToStaticMarkup(<AppealRecords {...props} {...overrides} />);
  assert.match(render(), /새 검사 요청 · 이의제기에 연결/);
  assert.doesNotMatch(render({ operator: false }), /<form/);
  assert.doesNotMatch(render({ appeals: [{ ...appeal, status: "RESOLVED" }] }), /<form/);
  assert.doesNotMatch(render({ releases: [changed] }), /<form/);
  assert.match(render({ busy: true }), /disabled=""/);
  const linked: Appeal = { ...appeal, rescan: { scanId: "synthetic-linked-scan", releaseId: changed.releaseId, policyHash: policy.policyHash, requestedAt: appeal.createdAt } };
  const scan: Scan = { scanId: linked.rescan!.scanId, releaseId: changed.releaseId, policyHash: policy.policyHash, appealId: appeal.appealId, status: "COMPLETED", stage: "COMPLETED", attempts: 1, maxAttempts: 3, traceId: "synthetic-trace", createdAt: appeal.createdAt, updatedAt: appeal.createdAt, nextAttemptAt: appeal.createdAt, result: { verdict: "PASS", state: "READY_FOR_VALIDATORS", reportRoot: "new-report-root", semanticEvidenceMode: "LOCAL_CONTRACT_TEST", providerQuality: "PROVIDER_QUALITY_NOT_MEASURED" } };
  assert.equal(linkedAppealScan(linked, scan), true);
  const html = render({ appeals: [linked], scans: [scan] });
  assert.match(html, /new-report-root/); assert.ok(html.includes(release.reportRoot!)); assert.match(html, /검사 작업 완료 · 실행 승인 아님/); assert.match(html, /상용 AI 모델의 탐지 품질을 측정하거나 승인한 결과가 아닙니다/); assert.doesNotMatch(html, /<form/);
  assert.match(render({ appeals: [linked], scans: [{ ...scan, result: { ...scan.result, semanticEvidenceMode: undefined, providerQuality: undefined } }] }), /분석 모드 확인 불가/);
  for (const invalid of [undefined, { ...scan, scanId: "other" }, { ...scan, releaseId: release.releaseId }, { ...scan, policyHash: "other" }, { ...scan, appealId: "other" }]) {
    assert.equal(linkedAppealScan(linked, invalid), false);
    const unknown = render({ appeals: [linked], scans: invalid ? [invalid] : [] });
    assert.match(unknown, /현재 검사 상태 미확인/); assert.doesNotMatch(unknown, /new-report-root|READY_FOR_VALIDATORS/);
    assert.match(unknown, /연결된 검사 현재 결과 조회/);
  }
  assert.match(render({ appeals: [linked], scans: [{ ...scan, status: "DEAD_LETTER" }] }), /검사 처리 실패/);
});
