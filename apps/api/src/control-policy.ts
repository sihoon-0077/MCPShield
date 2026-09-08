export const defaultPolicy = {
  version: "1.0.0", validitySeconds: 86400, requiredTiers: ["static", "semantic", "sandbox"],
  failClosed: true, maxArtifactBytes: 16777216, maxDailyScans: 100, maxQueuedScans: 20,
  deterministicRevocationRequired: true,
};
export const preparedPolicy = { ...defaultPolicy, profile: "restricted-node-docker-v1", requireRemoteAi: true, requireCritic: true };
export function validPolicy(document: any): boolean {
  const prepared = document?.profile === preparedPolicy.profile;
  return document && !Array.isArray(document) && Object.keys(document).sort().join() === Object.keys(prepared ? preparedPolicy : defaultPolicy).sort().join()
    && (!prepared || document.requireRemoteAi === true && document.requireCritic === true)
    && document.version === "1.0.0" && document.failClosed === true && document.deterministicRevocationRequired === true
    && Number.isInteger(document.validitySeconds) && document.validitySeconds >= 60 && document.validitySeconds <= 2592000
    && Number.isInteger(document.maxArtifactBytes) && document.maxArtifactBytes >= 1024 && document.maxArtifactBytes <= 16777216
    && Number.isInteger(document.maxDailyScans) && document.maxDailyScans >= 1 && document.maxDailyScans <= 1000
    && Number.isInteger(document.maxQueuedScans) && document.maxQueuedScans >= 1 && document.maxQueuedScans <= 100
    && Array.isArray(document.requiredTiers) && [...document.requiredTiers].sort().join() === "sandbox,semantic,static";
}
export function policyVerdict(bundle: any, scanResult: any, policy: any = defaultPolicy, runtimeTrust?: Record<string, any>) {
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
import { isDeepStrictEqual } from "node:util";
import { checkedPreparedEvidence } from "./prepared-evidence.js";
// @ts-expect-error Shared strict pure policy assessment is ESM JavaScript.
import { assessPreparedPolicy } from "../../../services/scanner/src/prepared-policy.mjs";
