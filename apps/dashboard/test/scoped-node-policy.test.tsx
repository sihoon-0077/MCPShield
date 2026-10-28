import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { PreparationDetail, PreparationRecords, isPreparationPolicy, preparationPolicyMatchesRelease, type Preparation } from "../components/preparation-console";
import { ReleaseWorkflow, SemanticEvidenceNotice, isBaselinePolicy, policyMatchesRelease, scopedNodePolicyMode, semanticModeLabel, type Release, type Scan, type SemanticEvidenceScope } from "../components/release-workflow";
import { BaselineSelect, baselineCandidates, baselineRequestFields } from "../components/baseline-selection";
import { ScanRequestForm, scanPolicyAllowed } from "../components/scan-request-form";
// @ts-expect-error Shared exact semantic policy constructor is ESM JavaScript.
import { scopedReviewPolicy, scopedBaselineReviewPolicy } from "../../../services/scanner/src/scoped-policy.mjs";

const source: Release = { releaseId: `0x${"1".repeat(64)}`, legacyReleaseId: "synthetic@1.0.0", toolId: "synthetic", version: "1.0.0", status: "UNVERIFIED", artifactDigest: `sha256:${"2".repeat(64)}`, toolSurfaceHash: `0x${"3".repeat(64)}`, policyHash: null, reportRoot: null, validUntil: null, chain: null, sourceType: "npm" };
const policy = (mode: string, baseline = false) => ({ policyHash: `0x${(baseline ? mode === "LOCAL_CONTRACT_TEST" ? "6" : "7" : mode === "LOCAL_CONTRACT_TEST" ? "4" : "5").repeat(64)}`, alias: mode, version: baseline ? "2.1.0" : "2.0.0", deprecatedAt: null,
  document: { version: baseline ? "2.1.0" : "2.0.0", profile: "restricted-node-docker-v2", semantic: baseline ? scopedBaselineReviewPolicy(mode) : scopedReviewPolicy(mode) } });
const policies = [policy("LOCAL_CONTRACT_TEST"), policy("PROVIDER_EXECUTION"), policy("LOCAL_CONTRACT_TEST", true), policy("PROVIDER_EXECUTION", true)];
const runtime = (mode?: string): Release => ({ ...source, runtimeProfile: "restricted-node-docker-v2", sourceType: "prepared-npm", semanticEvidenceMode: mode, providerQuality: "PROVIDER_QUALITY_NOT_MEASURED" });

test("Node v2 preparation selection requires exact semantic policy, preserves v1 and rejects OCI v2", () => {
  for (const valid of policies) {
    assert.equal(isPreparationPolicy(valid), true);
    assert.equal(scopedNodePolicyMode(valid.document), valid.document.semantic.evidenceMode);
    for (const sourceType of ["npm", "tarball"]) assert.equal(preparationPolicyMatchesRelease({ ...source, sourceType }, valid), true);
    for (const target of [undefined, { ...source, sourceType: "oci" }, runtime("LOCAL_CONTRACT_TEST")]) assert.equal(preparationPolicyMatchesRelease(target, valid), false);
    for (const edit of [
      (value: any) => { value.deprecatedAt = "2026-09-19"; },
      (value: any) => { value.document.profile = "restricted-oci-offline-v2"; },
      (value: any) => { delete value.document.version; },
      (value: any) => { value.document.version = value.document.version === "2.0.0" ? "2.1.0" : "2.0.0"; },
      (value: any) => { delete value.document.semantic; },
      (value: any) => { value.document.semantic.evidenceMode = "UNKNOWN"; },
      (value: any) => { value.document.semantic.privacyScope.providerQuality = "CERTIFIED"; },
      (value: any) => { value.document.semantic.limits.inputBytes++; },
      (value: any) => { value.document.semantic.extra = true; },
    ]) { const invalid = structuredClone(valid); edit(invalid); assert.equal(preparationPolicyMatchesRelease(source, invalid), false); }
  }
  const legacy = { ...policies[0], document: { profile: "restricted-node-docker-v1" } };
  assert.equal(preparationPolicyMatchesRelease(source, legacy), true);
  assert.equal(policyMatchesRelease({ ...source, runtimeProfile: "restricted-node-docker-v1" }, legacy), true);
  const oci = { ...legacy, document: { profile: "restricted-oci-offline-v1", semanticEvidenceMode: "LOCAL_CONTRACT_TEST" } };
  assert.equal(preparationPolicyMatchesRelease({ ...source, sourceType: "oci" }, oci), true);
  assert.equal(preparationPolicyMatchesRelease(source, oci), false);
});

test("normal scans, appeals and workflow cannot select v1/cross-mode/missing-mode Node v2 policies", () => {
  for (const selected of policies) {
    const release = runtime(selected.document.semantic.evidenceMode), other = policies.find(value => value.document.semantic.evidenceMode !== selected.document.semantic.evidenceMode)!;
    const appeal = { appealId: "synthetic-appeal", toolId: source.toolId, artifactDigest: source.artifactDigest, policyHash: other.policyHash };
    assert.equal(policyMatchesRelease(release, selected), true);
    assert.equal(scanPolicyAllowed(release, selected, appeal), true);
    assert.equal(scanPolicyAllowed(release, selected, { ...appeal, policyHash: selected.policyHash }), false, "same source/policy is not an appeal rescan");
    for (const invalid of [other, { ...selected, document: { profile: "restricted-node-docker-v1" } }, { ...selected, document: { profile: "restricted-node-docker-v2" } }]) {
      assert.equal(policyMatchesRelease(release, invalid), false);
      assert.equal(scanPolicyAllowed(release, invalid, appeal), false);
    }
    const html = renderToStaticMarkup(<ReleaseWorkflow release={release} scans={[]} policies={policies} actions={[]} manage={false} onRefresh={async () => {}} />);
    assert.match(html, new RegExp(`value="${selected.policyHash}"`)); assert.doesNotMatch(html, new RegExp(`value="${other.policyHash}"`));
  }
  for (const mode of [undefined, "", "UNKNOWN", ["LOCAL_CONTRACT_TEST"] as unknown as string]) {
    for (const selected of policies) assert.equal(policyMatchesRelease(runtime(mode), selected), false);
    const html = renderToStaticMarkup(<ScanRequestForm releases={[runtime(mode)]} policies={policies} onRefresh={async () => {}} />);
    assert.doesNotMatch(html, new RegExp(`value="${source.releaseId}"`)); assert.match(html, /조건에 맞는 릴리스·활성 정책이 없습니다/);
  }
});

test("2.1 baseline choices use only known public scope and revalidate exact null/ID against changed selections", () => {
  const selected = policies[2], before = { ...runtime("LOCAL_CONTRACT_TEST"), releaseId: `0x${"a".repeat(64)}`, sourceReleaseId: `0x${"b".repeat(64)}` };
  const current = { ...runtime("LOCAL_CONTRACT_TEST"), sourceReleaseId: source.releaseId, releaseId: `0x${"c".repeat(64)}` };
  assert.equal(isBaselinePolicy(selected.document), true); assert.equal(isBaselinePolicy(policies[0].document), false);
  for (const status of ["VERIFIED", "UNVERIFIED", "REVOKED"]) {
    const candidate = { ...before, status };
    assert.deepEqual(baselineCandidates([candidate], source, selected.document), [candidate], "old status is not approval inheritance or proof verification");
    assert.deepEqual(baselineRequestFields([candidate], current, selected.document, candidate.releaseId), { baselineReleaseId: candidate.releaseId });
  }
  assert.deepEqual(baselineRequestFields([before], source, selected.document, "none"), { baselineReleaseId: null });
  assert.notEqual(JSON.stringify({ policyHash: selected.policyHash, ...baselineRequestFields([before], source, selected.document, "none") }),
    JSON.stringify({ policyHash: selected.policyHash, ...baselineRequestFields([before], source, selected.document, before.releaseId) }), "idempotency signature distinguishes null from ID");
  for (const invalid of ["", "null", source.releaseId, before.sourceReleaseId, undefined, null, [before.releaseId], { releaseId: before.releaseId }]) {
    assert.throws(() => baselineRequestFields([before], source, selected.document, invalid as string), /다시 선택/);
  }
  for (const change of [{ toolId: "other" }, { releaseId: source.releaseId }, { sourceReleaseId: source.releaseId }, { sourceReleaseId: undefined },
    { sourceReleaseId: "<script>private-path</script>" }, { runtimeProfile: "restricted-node-docker-v1" }, { runtimeProfile: "restricted-oci-offline-v1" },
    { sourceType: "npm" }, { semanticEvidenceMode: undefined }, { semanticEvidenceMode: "UNKNOWN" }, { semanticEvidenceMode: "PROVIDER_EXECUTION" }]) {
    const changed = { ...before, ...change };
    assert.deepEqual(baselineCandidates([changed], source, selected.document), []);
    assert.throws(() => baselineRequestFields([changed], source, selected.document, before.releaseId), /다시 선택/);
  }
  for (const target of [undefined, { ...source, sourceType: "oci" }, { ...source, toolId: "other" }, { ...current, sourceReleaseId: before.sourceReleaseId },
    { ...current, sourceReleaseId: undefined }, { ...current, semanticEvidenceMode: "PROVIDER_EXECUTION" }]) {
    assert.deepEqual(baselineCandidates([before], target, selected.document), []);
    assert.throws(() => baselineRequestFields([before], target, selected.document, before.releaseId), /다시 선택/);
  }
  assert.throws(() => baselineRequestFields([], source, selected.document, before.releaseId), /다시 선택/, "removed inventory must not be sent from stale state");
  assert.throws(() => baselineRequestFields([before], source, policies[3].document, before.releaseId), /다시 선택/, "a policy-mode change invalidates the old candidate");
  for (const document of [policies[0].document, policies[1].document, { profile: "restricted-node-docker-v1" }, { profile: "restricted-oci-offline-v1" }, {}]) {
    assert.deepEqual(baselineRequestFields([before], source, document, before.releaseId), {}, "legacy/2.0/OCI payloads retain their old fields");
    assert.deepEqual(baselineCandidates([before], source, document), []);
  }
  // Static markup only; actual selection events/hydration are checked separately in a browser.
  const html = renderToStaticMarkup(<BaselineSelect candidates={[before]} value="" disabled={false} onChange={() => {}} />);
  assert.match(html, /name="baselineReleaseId" required=""/); assert.match(html, /비교 방법을 직접 선택하세요/);
  assert.match(html, /value="none"/); assert.match(html, /API가 최종 확인/); assert.match(html, /현재 코드의 위험 검사는 진행/);
  assert.match(html, new RegExp(before.releaseId)); assert.doesNotMatch(html, /type="password"|private-path/);
});

test("semantic labels distinguish provider policy from local fixtures and never infer execution, quality or missing metadata", () => {
  for (const selected of policies) {
    const mode = selected.document.semantic.evidenceMode;
    const html = renderToStaticMarkup(<SemanticEvidenceNotice evidence={runtime(mode)} />);
    assert.ok(html.includes(semanticModeLabel(mode))); assert.match(html, /모델 품질은 미측정/); assert.match(html, /현재 실행 허가는 별도로 확인/);
    if (mode === "PROVIDER_EXECUTION") { assert.match(html, /이 모드 표시는 호출 수행·성공이나 탐지 품질을 증명하지 않습니다/); assert.doesNotMatch(html, /로컬 합성 응답으로|외부 모델 호출을 실제 수행/); }
    else { assert.match(html, /로컬 합성 응답으로/); assert.doesNotMatch(html, /외부 모델 호출을 실제 수행/); }
  }
  for (const evidence of [undefined, {}, { semanticEvidenceMode: "<script>claimed-provider</script>", providerQuality: "CERTIFIED" }, { semanticEvidenceMode: {}, providerQuality: [] }]) {
    const html = renderToStaticMarkup(<SemanticEvidenceNotice evidence={evidence as SemanticEvidenceScope} required />);
    assert.match(html, /분석 모드 확인 불가/); assert.match(html, /미제공 또는 알 수 없는 값/); assert.match(html, /분석 모드를 임의로 추정하지 않습니다/);
    assert.doesNotMatch(html, /<script>|CERTIFIED|외부 모델 호출을 실제 수행|로컬 합성 응답으로/);
  }
  const job: Preparation = { preparationId: "synthetic-job", sourceReleaseId: source.releaseId, policyHash: policies[0].policyHash, status: "COMPLETED", attempts: 1, maxAttempts: 3, traceId: "synthetic-trace", createdAt: "2026-09-19T00:00:00Z", updatedAt: "2026-09-19T00:00:00Z", result: { outcome: "DISCOVERED", verdict: "ABSTAIN", reportRoot: "synthetic-root", issues: [] } };
  for (const html of [renderToStaticMarkup(<PreparationRecords jobs={[job]} releases={[source]} operator={false} />),
    renderToStaticMarkup(<PreparationDetail job={job} operator={false} summary={null} />),
    renderToStaticMarkup(<ReleaseWorkflow release={{ ...runtime(), providerQuality: undefined }} scans={[]} policies={policies} actions={[]} manage={false} onRefresh={async () => {}} />)]) assert.match(html, /분석 모드 확인 불가/);
  // No provider call is made by this fixture. Policy metadata can exist even after preflight ABSTAIN.
  const scan: Scan = { scanId: "no-provider-execution", releaseId: source.releaseId, policyHash: policies[1].policyHash, status: "COMPLETED", stage: "COMPLETED", attempts: 1, maxAttempts: 3, traceId: job.traceId, createdAt: job.createdAt, updatedAt: job.updatedAt, nextAttemptAt: job.updatedAt,
    result: { semanticEvidenceMode: "PROVIDER_EXECUTION", providerQuality: "PROVIDER_QUALITY_NOT_MEASURED", verdict: "ABSTAIN", state: "READY_FOR_VALIDATORS", scanResult: { scanStatus: "INCONCLUSIVE" } } };
  const abstain = renderToStaticMarkup(<ReleaseWorkflow release={runtime("PROVIDER_EXECUTION")} scans={[scan]} policies={policies} actions={[]} manage={false} onRefresh={async () => {}} />);
  assert.match(abstain, /ABSTAIN/); assert.match(abstain, /INCONCLUSIVE/); assert.match(abstain, /이 모드 표시는 호출 수행·성공이나 탐지 품질을 증명하지 않습니다/);
  assert.doesNotMatch(abstain, /실제 수행한 범위|API: ALLOW|호출 성공 기록/);
});
