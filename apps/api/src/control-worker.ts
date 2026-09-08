import { randomUUID } from "node:crypto";
import { ControlStore } from "./control-store.js";
import { saveEvidence, type ControlOptions } from "./control-plane.js";
import { withSpan } from "../../../packages/telemetry/index.mjs";
import { policyVerdict, preparedPolicy, ociPolicy, assertRuntimeBudget, validPolicy } from "./control-policy.js";
import { scanPreparedRelease } from "./preparation-worker.js";
// @ts-expect-error Scanner evidence is shared ESM JavaScript.
import { verifyEvidenceBundle } from "../../../services/scanner/src/evidence.mjs";

export async function runControlWorkerOnce(store: ControlStore, options: ControlOptions, owner = randomUUID()) {
  // Existing bounded claim fence covers closure export + three probes + full AI/critic review, not a 3-minute partial lease.
  const scan = await store.claim(owner, 20 * 60 * 1000);
  if (!scan) return false;
  try {
    const release = await store.get(scan.tenantId, "release", scan.releaseId);
    const policy = await store.get(scan.tenantId, "policy", scan.policyHash);
    if (!release || !policy || policy.deprecatedAt) throw new Error("INPUT_NO_LONGER_AVAILABLE");
    if (!validPolicy(policy.document)) throw new Error("UNSUPPORTED_POLICY");
    const oci = release.runtimeProfile === ociPolicy.profile, prepared = release.runtimeProfile === preparedPolicy.profile || oci;
    if ((release.runtimeProfile ?? null) !== (policy.document.profile ?? null)) throw new Error("SCAN_PROFILE_MISMATCH");
    assertRuntimeBudget(release, policy.document);
    const baseline = scan.request.baselineReleaseId ? await store.get(scan.tenantId, "release", scan.request.baselineReleaseId) : undefined;
    // @ts-expect-error Scanner runtime is shared ESM JavaScript.
    const execute = options.scanArtifact ?? (await import("../../../services/scanner/src/scanner.mjs")).scanResolvedArtifact;
    const result = await withSpan("scan.execute", { "mcpshield.scan_id": scan.scanId, "mcpshield.release_id": scan.releaseId }, () => prepared ? scanPreparedRelease(scan, release, options) : execute({ artifactDir: release.artifactDir, baselineDir: baseline?.artifactDir,
      scanId: scan.scanId, policy: policy.document, sourceType: release.sourceType,
      // The dedicated scanner entrypoint never executes arbitrary code on the host.
      ...options.scannerOptions,
      sandbox: options.scannerOptions?.sandbox ?? (process.env.CONTROL_SANDBOX_MODE === "docker" ? "docker" : undefined) }), { traceparent: scan.request.traceparent });
    if (result.result?.artifactDigest !== release.artifactDigest || result.result?.toolSurfaceHash !== release.toolSurfaceHash) throw new Error("ARTIFACT_DIGEST_CHANGED");
    if (!result.bundle?.manifest?.root) throw new Error("EVIDENCE_ROOT_MISSING");
    if (!verifyEvidenceBundle(result.bundle, result.bundle.manifest.root)) throw new Error("EVIDENCE_INTEGRITY_MISMATCH");
    if (oci) assertRuntimeBudget(release, policy.document, result.binding?.descriptor);
    const verdict = policyVerdict(result.bundle, result.result, policy.document, oci ? result.ociRuntimeTrust : result.preparedRuntimeTrust);
    const completedAt = Date.now(), validFrom = new Date(completedAt).toISOString(), validUntil = new Date(completedAt + policy.document.validitySeconds * 1000).toISOString();
    const evidenceKey = await saveEvidence(options, scan.tenantId, result.bundle);
    const completedResult = { scanResult: result.result, reportRoot: result.bundle.manifest.root,
      analysis: result.analysis, policyHash: scan.policyHash, validFrom, validUntil, evidenceKey, verdict,
      ...(oci ? { ociRuntimeTrust: result.ociRuntimeTrust, semanticEvidenceMode: policy.document.semanticEvidenceMode, providerQuality: "PROVIDER_QUALITY_NOT_MEASURED" }
        : prepared ? { preparedRuntimeTrust: result.preparedRuntimeTrust } : {}), state: verdict === "ABSTAIN" ? "REVIEW_REQUIRED" : "READY_FOR_VALIDATORS" };
    await store.forTenant(scan.tenantId, async tx => {
      if (await tx.finish(scan, owner, completedResult)) await tx.scanOutcome(scan, "completed", { reportRoot: result.bundle.manifest.root, status: result.result.scanStatus, verdict });
    });
  } catch (error: any) {
    const raw = typeof error?.code === "string" ? error.code : error?.message;
    const code = /^[A-Z][A-Z0-9_]{0,80}$/.test(raw ?? "") ? raw : "SCAN_EXECUTION_FAILED";
    const retryable = /TIMEOUT|UNAVAILABLE|WORKER_LOST|RATE_LIMIT|ECONN|ENOTFOUND|TRANSIENT/.test(code);
    await store.forTenant(scan.tenantId, async tx => {
      if (await tx.fail(scan, owner, code, retryable)) await tx.scanOutcome(scan, "failed", { code, retryable });
    });
  }
  return true;
}
