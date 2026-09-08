import { randomUUID } from "node:crypto";
import { ControlStore } from "./control-store.js";
import { hash, saveEvidence, type ControlOptions } from "./control-plane.js";
import { claimPreparation, failPreparation, preparations, type PreparationJob } from "./preparation-store.js";
import { preparedTrust } from "./prepared-config.js";
import { preparedPolicy, policyVerdict, validPolicy } from "./control-policy.js";
import { sourceIdentity } from "./preparation-control.js";
import { checkedPreparedEvidence } from "./prepared-evidence.js";
import { traceHeaders, withSpan } from "../../../packages/telemetry/index.mjs";
// @ts-expect-error Shared evidence bundle implementation is ESM JavaScript.
import { createEvidenceBundle, verifyEvidenceBundle } from "../../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared canonical protocol schema is ESM JavaScript.
import { assertCanonicalScanResult } from "../../../services/scanner/src/protocol-schema.mjs";

function checkedConfig(options: ControlOptions, job: PreparationJob) {
  if (!options.preparedRuntime || options.scannerOptions?.sandbox !== "docker") throw new Error("PREPARATION_NOT_CONFIGURED");
  const trusted = preparedTrust(options.preparedRuntime);
  if (hash(trusted) !== job.configHash || hash(job.request.trustedConfig) !== job.configHash) throw new Error("PREPARATION_CONFIG_CHANGED");
  return trusted;
}
async function checkedInput(store: ControlStore, job: PreparationJob) {
  const [source, policy] = await Promise.all([store.get(job.tenantId, "release", job.sourceReleaseId), store.get(job.tenantId, "policy", job.policyHash)]);
  if (!source || !["npm", "tarball"].includes(source.sourceType) || hash(sourceIdentity(source)) !== hash(job.request.sourceIdentity)) throw new Error("SOURCE_IDENTITY_MISMATCH");
  if (!policy || policy.deprecatedAt || !validPolicy(policy.document) || policy.document.profile !== preparedPolicy.profile) throw new Error("PREPARATION_POLICY_UNAVAILABLE");
  if ((source.metadata?.expandedBytes ?? source.metadata?.sizeBytes ?? 0) > policy.document.maxArtifactBytes) throw new Error("ARTIFACT_TOO_LARGE");
  return { source, policy };
}
export async function runPreparationWorkerOnce(store: ControlStore, options: ControlOptions, owner = randomUUID()) {
  const job = await claimPreparation(store, owner); if (!job) return false;
  let output: any, transferred = false, finalizationStarted = false, cleanupSafe = true;
  try {
    const trusted = checkedConfig(options, job), { source, policy } = await checkedInput(store, job);
    // @ts-expect-error Shared prepared scanner is ESM JavaScript.
    const execute = options.prepareRuntime ?? (await import("../../../services/scanner/src/prepared-scan.mjs")).prepareAndScanRuntime;
    const { sandbox: _sandbox, ...ai } = options.scannerOptions!;
    output = await withSpan("scan.execute", { "mcpshield.release_id": job.sourceReleaseId }, () => execute({
      preparation: { root: source.artifactDir, sourceDigest: source.metadata?.archiveDigest ?? source.artifactDigest, sourceTreeDigest: source.artifactDigest,
        builderImageDigest: trusted.builderImageDigest, platform: trusted.platform, ...(trusted.binName ? { binName: trusted.binName } : {}) },
      sourceReleaseId: job.sourceReleaseId, releaseId: source.legacyReleaseId, scanId: job.preparationId, ai, trusted }), { traceparent: job.request.traceparent });
    checkedConfig(options, job);
    const issues = (output.analysis?.issues ?? []).filter((code: any) => typeof code === "string" && /^[A-Z][A-Z0-9_]{0,100}$/.test(code)).slice(0, 32);
    const originalBundle = output.bundle ?? (!output.binding && !output.result ? createEvidenceBundle({ "prepared/failure.json": {
      profile: preparedPolicy.profile, outcome: "INCONCLUSIVE", verdict: "ABSTAIN", issues } }) : undefined);
    if (!originalBundle?.manifest?.root || !verifyEvidenceBundle(originalBundle, originalBundle.manifest.root)) throw new Error("EVIDENCE_INTEGRITY_MISMATCH");
    const bundle = createEvidenceBundle({ ...Object.fromEntries(Object.entries(originalBundle.files).map(([path, content]) => [path, JSON.parse(content as string)])),
      "prepared/source-identity.json": sourceIdentity(source) });
    const evidenceKey = await saveEvidence(options, job.tenantId, bundle);
    let derived: Record<string, any> | undefined, scanResult: Record<string, any> | undefined;
    if (output.binding) {
      assertCanonicalScanResult(output.result);
      const { binding, identity } = checkedPreparedEvidence(bundle);
      if (hash(binding) !== hash(output.binding) || binding.sourceReleaseId !== source.releaseId || binding.sourceArtifactDigest !== source.artifactDigest
        || output.result?.scanId !== job.preparationId || output.result?.releaseId !== source.legacyReleaseId
        || output.result?.artifactDigest !== binding.artifactDigest || output.result?.toolSurfaceHash !== binding.toolSurfaceHash
        || binding.descriptor.builderImageDigest !== trusted.builderImageDigest || hash(binding.platform) !== hash(trusted.platform)) throw new Error("PREPARED_RELEASE_IDENTITY_MISMATCH");
      const verdict = policyVerdict(bundle, output.result, policy.document, trusted);
      const now = Date.now();
      scanResult = { scanResult: output.result, reportRoot: bundle.manifest.root, analysis: output.analysis, policyHash: job.policyHash,
        validFrom: new Date(now).toISOString(), validUntil: new Date(now + policy.document.validitySeconds * 1000).toISOString(), evidenceKey,
        verdict, state: verdict === "ABSTAIN" ? "REVIEW_REQUIRED" : "READY_FOR_VALIDATORS" };
      if (typeof output.runtimeTag !== "string" || !/^mcpshield-runtime-[a-f0-9-]{36}:local$/.test(output.runtimeTag) || typeof output.cleanup !== "function") throw new Error("PREPARED_IMAGE_OWNERSHIP_MISSING");
      derived = { ...identity, artifactDigest: binding.artifactDigest, manifestDigest: binding.manifestDigest, toolSurfaceHash: binding.toolSurfaceHash,
        legacyReleaseId: source.legacyReleaseId, version: source.version, sourceType: "prepared-npm", runtimeProfile: preparedPolicy.profile, sourceReleaseId: source.releaseId,
        artifactUri: `prepared-local:${binding.artifactDigest}`, status: "UNVERIFIED", policyHash: null, reportRoot: null, validUntil: null, chain: null,
        preparedEvidenceKey: evidenceKey, preparedReportRoot: bundle.manifest.root, runtimeTag: output.runtimeTag, createdAt: new Date(now).toISOString() };
    }
    finalizationStarted = true;
    const committed = await withSpan("scan.accept", {}, () => store.forTenant(job.tenantId, async (tx) => {
      checkedConfig(options, job); await checkedInput(tx, job);
      const scanId = derived ? job.preparationId : undefined, now = new Date().toISOString();
      const result = { outcome: derived ? "DERIVED_RELEASE_CREATED" : "INCONCLUSIVE", ...(derived ? { releaseId: derived.releaseId, scanId, verdict: scanResult!.verdict } : { verdict: "ABSTAIN" }),
        evidenceKey, reportRoot: bundle.manifest.root, issues };
      const [updated] = await tx.query(`UPDATE cp_preparations SET state='COMPLETED',result_json=?,lease_owner=NULL,lease_expires_at=NULL,updated_at=?
        WHERE tenant_id=? AND preparation_id=? AND state='RUNNING' AND lease_owner=? AND lease_expires_at>? AND config_hash=? RETURNING preparation_id`,
        [JSON.stringify(result), now, job.tenantId, job.preparationId, owner, now, job.configHash]);
      if (!updated) return { transferred: false };
      let ownsImage = false;
      if (derived) {
        ownsImage = await tx.put(job.tenantId, "release", derived.releaseId, derived);
        if (!ownsImage) {
          const existing = await tx.get(job.tenantId, "release", derived.releaseId);
          checkedPreparedEvidence(bundle, existing);
          if (existing?.runtimeProfile !== preparedPolicy.profile) throw new Error("PREPARED_RELEASE_COLLISION");
        }
        const request = { releaseId: derived.releaseId, policyHash: job.policyHash, artifactDigest: derived.artifactDigest, preparationId: job.preparationId,
          ...traceHeaders() };
        await tx.query(`INSERT INTO cp_scans(scan_id,tenant_id,release_id,policy_hash,idempotency_key,request_hash,request_json,state,stage,
          attempts,max_attempts,next_attempt_at,trace_id,result_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'COMPLETED','DONE',1,3,?,?,?,?,?)`,
          [scanId!, job.tenantId, derived.releaseId, job.policyHash, randomUUID(), hash(request), JSON.stringify(request), now, job.traceId, JSON.stringify(scanResult), now, now]);
        await tx.event(job.tenantId, derived.releaseId, "scan.completed", { scanId, reportRoot: bundle.manifest.root, status: output.result.scanStatus }, job.traceId);
      }
      await tx.event(job.tenantId, job.sourceReleaseId, "preparation.completed", { preparationId: job.preparationId, outcome: result.outcome, ...(scanId ? { scanId, releaseId: derived!.releaseId } : {}) }, job.traceId);
      return { transferred: ownsImage };
    }), { traceparent: job.request.traceparent });
    transferred = committed.transferred;
  } catch (error: any) {
    if (finalizationStarted) {
      try {
        const [saved] = await preparations(store, job.tenantId, job.preparationId);
        const release = saved?.result?.releaseId ? await store.get(job.tenantId, "release", saved.result.releaseId) : undefined;
        transferred = saved?.status === "COMPLETED" && release?.runtimeTag === output?.runtimeTag && release?.preparedReportRoot === saved.result?.reportRoot;
      } catch { cleanupSafe = false; } // An uncertain DB commit must not delete an image whose ownership may have transferred.
    }
    const raw = error?.code ?? error?.message, code = /^[A-Z][A-Z0-9_]{0,100}$/.test(raw ?? "") ? raw : "PREPARATION_EXECUTION_FAILED";
    await failPreparation(store, job, owner, code, /TIMEOUT|UNAVAILABLE|WORKER_LOST|RATE_LIMIT|ECONN|ENOTFOUND|TRANSIENT/.test(code));
  } finally {
    // Cleanup only the closure helper's own random tag. A committed new row owns it thereafter.
    if (!transferred && cleanupSafe) try { await output?.cleanup?.(); } catch { /* no raw Docker errors or private metadata in logs */ }
  }
  return true;
}
