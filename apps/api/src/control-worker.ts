import { randomUUID } from "node:crypto";
import { ControlStore } from "./control-store.js";
import { saveEvidence, type ControlOptions } from "./control-plane.js";
import { withSpan } from "../../../packages/telemetry/index.mjs";
import { policyVerdict, validPolicy } from "./control-policy.js";
// @ts-expect-error Scanner evidence is shared ESM JavaScript.
import { verifyEvidenceBundle } from "../../../services/scanner/src/evidence.mjs";

export async function runControlWorkerOnce(store: ControlStore, options: ControlOptions, owner = randomUUID()) {
  const scan = await store.claim(owner, 20 * 60 * 1000);
  if (!scan) return false;
  try {
    const release = await store.get(scan.tenantId, "release", scan.releaseId);
    const policy = await store.get(scan.tenantId, "policy", scan.policyHash);
    if (!release || !policy || policy.deprecatedAt) throw new Error("INPUT_NO_LONGER_AVAILABLE");
    if (!validPolicy(policy.document)) throw new Error("UNSUPPORTED_POLICY");
    if ((release.metadata?.expandedBytes ?? release.metadata?.sizeBytes ?? 0) > policy.document.maxArtifactBytes) throw new Error("ARTIFACT_TOO_LARGE");
    const baseline = scan.request.baselineReleaseId ? await store.get(scan.tenantId, "release", scan.request.baselineReleaseId) : undefined;
    // @ts-expect-error Scanner runtime is shared ESM JavaScript.
    const execute = options.scanArtifact ?? (await import("../../../services/scanner/src/scanner.mjs")).scanResolvedArtifact;
    const result = await withSpan("scan.execute", { "mcpshield.scan_id": scan.scanId, "mcpshield.release_id": scan.releaseId }, () => execute({ artifactDir: release.artifactDir, baselineDir: baseline?.artifactDir,
      scanId: scan.scanId, policy: policy.document, sourceType: release.sourceType,
      // The dedicated scanner entrypoint never executes arbitrary code on the host.
      ...options.scannerOptions,
      sandbox: options.scannerOptions?.sandbox ?? (process.env.CONTROL_SANDBOX_MODE === "docker" ? "docker" : undefined) }), { traceparent: scan.request.traceparent });
    if (result.result?.artifactDigest !== release.artifactDigest || result.result?.toolSurfaceHash !== release.toolSurfaceHash) throw new Error("ARTIFACT_DIGEST_CHANGED");
    if (!result.bundle?.manifest?.root) throw new Error("EVIDENCE_ROOT_MISSING");
    if (!verifyEvidenceBundle(result.bundle, result.bundle.manifest.root)) throw new Error("EVIDENCE_INTEGRITY_MISMATCH");
    const verdict = policyVerdict(result.bundle, result.result);
    const validFrom = new Date().toISOString(), validUntil = new Date(Date.now() + policy.document.validitySeconds * 1000).toISOString();
    const evidenceKey = await saveEvidence(options, scan.tenantId, result.bundle);
    const completed = await store.finish(scan, owner, { scanResult: result.result, reportRoot: result.bundle.manifest.root,
      analysis: result.analysis, policyHash: scan.policyHash, validFrom, validUntil, evidenceKey, verdict, state: "READY_FOR_VALIDATORS" });
    if (completed) await store.event(scan.tenantId, scan.releaseId, "scan.completed", { scanId: scan.scanId, reportRoot: result.bundle.manifest.root, status: result.result.scanStatus }, scan.traceId);
  } catch (error: any) {
    const raw = typeof error?.code === "string" ? error.code : error?.message;
    const code = /^[A-Z][A-Z0-9_]{0,80}$/.test(raw ?? "") ? raw : "SCAN_EXECUTION_FAILED";
    const retryable = /TIMEOUT|UNAVAILABLE|WORKER_LOST|RATE_LIMIT|ECONN|ENOTFOUND|TRANSIENT/.test(code);
    if (await store.fail(scan, owner, code, retryable)) await store.event(scan.tenantId, scan.releaseId, "scan.failed", { scanId: scan.scanId, code, retryable }, scan.traceId);
  }
  return true;
}
