export const defaultPolicy = {
  version: "1.0.0", validitySeconds: 86400, requiredTiers: ["static", "semantic", "sandbox"],
  failClosed: true, maxArtifactBytes: 16777216, maxDailyScans: 100, maxQueuedScans: 20,
  deterministicRevocationRequired: true,
};
export const preparedPolicy = { ...defaultPolicy, profile: "restricted-node-docker-v1", requireRemoteAi: true, requireCritic: true };
export const scopedPreparedPolicy = (mode: "LOCAL_CONTRACT_TEST" | "PROVIDER_EXECUTION") => ({ ...preparedPolicy, version: "2.0.0", profile: SCOPED_NODE_PROFILE, semantic: scopedReviewPolicy(mode) });
export const isNodePreparedPolicy = (policy: any) => policy?.profile === preparedPolicy.profile || policy?.profile === SCOPED_NODE_PROFILE;
const { maxArtifactBytes: _nodeArtifactLimit, ...commonOciPolicy } = preparedPolicy;
export const ociPolicy = { ...commonOciPolicy, profile: "restricted-oci-offline-v1", semanticEvidenceMode: "LOCAL_CONTRACT_TEST",
  maxSourceBytes: 100 * 1024 * 1024, maxExpandedBytes: 512 * 1024 * 1024 };
export function validPolicy(document: any): boolean {
  if (document?.profile === SCOPED_NODE_PROFILE) {
    const { semantic, ...base } = document;
    return Object.keys(document).sort().join() === Object.keys(scopedPreparedPolicy("LOCAL_CONTRACT_TEST")).sort().join()
      && document.version === "2.0.0" && validateScopedReviewPolicy(semantic)
      && validPolicy({ ...base, version: "1.0.0", profile: preparedPolicy.profile });
  }
  const oci = document?.profile === ociPolicy.profile, prepared = document?.profile === preparedPolicy.profile || oci;
  return document && !Array.isArray(document) && Object.keys(document).sort().join() === Object.keys(oci ? ociPolicy : prepared ? preparedPolicy : defaultPolicy).sort().join()
    && (!prepared || document.requireRemoteAi === true && document.requireCritic === true)
    && document.version === "1.0.0" && document.failClosed === true && document.deterministicRevocationRequired === true
    && Number.isInteger(document.validitySeconds) && document.validitySeconds >= 60 && document.validitySeconds <= 2592000
    && (oci ? document.semanticEvidenceMode === "LOCAL_CONTRACT_TEST" && document.maxSourceBytes === 100 * 1024 * 1024
      && Number.isInteger(document.maxExpandedBytes) && document.maxExpandedBytes >= 1024 && document.maxExpandedBytes <= 512 * 1024 * 1024
      : Number.isInteger(document.maxArtifactBytes) && document.maxArtifactBytes >= 1024 && document.maxArtifactBytes <= 16777216)
    && Number.isInteger(document.maxDailyScans) && document.maxDailyScans >= 1 && document.maxDailyScans <= 1000
    && Number.isInteger(document.maxQueuedScans) && document.maxQueuedScans >= 1 && document.maxQueuedScans <= 100
    && Array.isArray(document.requiredTiers) && [...document.requiredTiers].sort().join() === "sandbox,semantic,static";
}
export function policyVerdict(bundle: any, scanResult: any, policy: any = defaultPolicy, runtimeTrust?: Record<string, any>) {
  if (policy.profile === SCOPED_NODE_PROFILE) {
    if (!validPolicy(policy) || !runtimeTrust?.sourceProvenance) return "ABSTAIN";
    const { binding } = checkedPreparedEvidence(bundle);
    if (binding.executionPolicy.profile !== SCOPED_NODE_PROFILE || !isDeepStrictEqual(binding.executionPolicy.semantic, policy.semantic)) return "ABSTAIN";
    const budget = runtimeTrust.sourceBudget;
    if (!budget || budget.sourceArtifactDigest !== binding.sourceArtifactDigest || !Number.isSafeInteger(budget.sourceBytes)
      || budget.sourceBytes < 0 || budget.sourceBytes > policy.maxArtifactBytes) return "ABSTAIN";
    return scopedAssessment.assessScopedPreparedPolicy(bundle, scanResult, binding, runtimeTrust).verdict as "PASS" | "FAIL" | "ABSTAIN";
  }
  if (policy.profile === ociPolicy.profile) {
    if (!validPolicy(policy) || !runtimeTrust) return "ABSTAIN";
    const { binding, source } = checkedOciEvidence(bundle);
    assertRuntimeBudget(source, policy, binding.descriptor);
    return assessOciPolicy(bundle, scanResult, binding, runtimeTrust).verdict as "PASS" | "FAIL" | "ABSTAIN";
  }
  if (bundle.files["oci/binding.json"] !== undefined) return "ABSTAIN";
  // Prepared evidence must never fall through the legacy policy's broader completion gate.
  if (policy.profile === preparedPolicy.profile) {
    if (!validPolicy(policy) || !runtimeTrust) return "ABSTAIN";
    const { binding } = checkedPreparedEvidence(bundle);
    return assessPreparedPolicy(bundle, scanResult, binding, runtimeTrust).verdict as "PASS" | "FAIL" | "ABSTAIN";
  }
  if (policy.profile !== undefined || bundle.files["prepared/binding.json"] !== undefined) return "ABSTAIN";
  const report = JSON.parse(bundle.files["report.json"] ?? "null"), sandbox = JSON.parse(bundle.files["sandbox/events.json"] ?? "null");
  const semantic = JSON.parse(bundle.files["semantic/model-output.json"] ?? "null"), mcp = JSON.parse(bundle.files["sandbox/mcp.json"] ?? "null");
  if (!report || report.artifactDigest !== scanResult.artifactDigest || report.toolSurfaceHash !== scanResult.toolSurfaceHash
    || report.scanStatus !== scanResult.scanStatus || !isDeepStrictEqual(report.findings, scanResult.findings)) throw new Error("EVIDENCE_RESULT_MISMATCH");
  const critical = scanResult.findings?.some((finding: any) => finding.deterministic === true && ["HIGH", "CRITICAL"].includes(finding.severity) && finding.stage !== "AI");
  if (scanResult.scanStatus === "FAILED" && critical) return "FAIL";
  if (semantic?.execution?.status === "REVIEW_REQUIRED" || semantic?.execution?.needsHumanReview || semantic?.report?.needsHumanReview) return "ABSTAIN";
  if (scanResult.scanStatus === "PASSED" && !critical && report.scope === "STATIC_AI_SANDBOX" && sandbox?.mode === "DOCKER" && sandbox.complete === true
    && mcp?.complete === true && Array.isArray(JSON.parse(bundle.files["static/findings.json"] ?? "null")) && Array.isArray(semantic?.findings)) return "PASS";
  return "ABSTAIN";
}
export function assertRuntimeBudget(source: any, policy: any, descriptor?: any) {
  if (policy.profile === ociPolicy.profile) {
    if (!validPolicy(policy)) throw new Error("UNSUPPORTED_POLICY");
    // The resolver/importer independently enforce the fixed 100MiB source snapshot.
    // The 512MiB policy applies to expanded layers + native export, NOT source download.
    if (descriptor && (!Number.isSafeInteger(descriptor.sourceBytes) || descriptor.sourceBytes < 0 || descriptor.sourceBytes > policy.maxSourceBytes
      || !Number.isSafeInteger(descriptor.layerArchiveBytes) || descriptor.layerArchiveBytes < 0
      || !Number.isSafeInteger(descriptor.exportArchiveBytes) || descriptor.exportArchiveBytes < 0
      || descriptor.layerArchiveBytes + descriptor.exportArchiveBytes > policy.maxExpandedBytes)) throw new Error("OCI_RUNTIME_BUDGET_EXCEEDED");
    if ((source.metadata?.sourceBytes ?? source.metadata?.sizeBytes ?? 0) > policy.maxSourceBytes) throw new Error("OCI_SOURCE_BUDGET_EXCEEDED");
  } else if ((source.metadata?.expandedBytes ?? source.metadata?.sizeBytes ?? 0) > policy.maxArtifactBytes) throw new Error("ARTIFACT_TOO_LARGE");
}
import { isDeepStrictEqual } from "node:util";
import { checkedPreparedEvidence, checkedOciEvidence } from "./prepared-evidence.js";
// @ts-expect-error Shared strict pure policy assessment is ESM JavaScript.
import { assessPreparedPolicy } from "../../../services/scanner/src/prepared-policy.mjs";
// @ts-expect-error Separate scoped v2 assessor never reuses v1 authorization.
import * as scopedAssessment from "../../../services/scanner/src/prepared-policy.mjs";
// @ts-expect-error Shared frozen scoped commitment.
import { SCOPED_NODE_PROFILE, scopedReviewPolicy, validateScopedReviewPolicy } from "../../../services/scanner/src/scoped-policy.mjs";
// @ts-expect-error Shared strict OCI policy is separate from Node and legacy approval.
import { assessOciPolicy } from "../../../services/scanner/src/oci-policy.mjs";
