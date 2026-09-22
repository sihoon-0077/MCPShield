import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { hash, type ControlOptions } from "./control-plane.js";
import { preparedTrust } from "./prepared-config.js";
import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2.js";
// @ts-expect-error Local immutable acquisition reuses the bounded stable snapshot.
import { resolveArtifact } from "../../../services/resolver/src/resolver.mjs";
// @ts-expect-error Shared exact provenance/policy contracts.
import { checkedScopedProvenance, SCOPED_NODE_PROFILE, validateScopedReviewPolicy } from "../../../services/scanner/src/scoped-policy.mjs";
// @ts-expect-error Shared immutable execution commitment.
import { scopedPreparedExecutionPolicy } from "../../../services/scanner/src/prepared-binding.mjs";
// @ts-expect-error Shared transport/privacy validator; no provider request is made here.
import * as scopedSemantic from "../../../services/scanner/src/scoped-semantic.mjs";

export type ScopedAi = Record<string, any>;
export function checkedScopedAi(ai: ScopedAi, semantic: any) {
  scopedSemantic.validateScopedAiV2(ai, semantic);
  return structuredClone(ai);
}
export interface ScopedPreparedConfig { provenancePaths: Record<string, string>; ai: ScopedAi }
const exact = (value: any, keys: string[]) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join() === keys.sort().join();
export function checkedScopedConfig(value: any): ScopedPreparedConfig {
  if (!exact(value, ["provenancePaths", "ai"]) || !value.provenancePaths || typeof value.provenancePaths !== "object" || Array.isArray(value.provenancePaths)
    || Object.entries(value.provenancePaths).length > 128 || Object.entries(value.provenancePaths).some(([tenant, path]) => !/^[A-Za-z0-9_-]{1,64}$/.test(tenant)
      || typeof path !== "string" || path.length > 4096 || !isAbsolute(path) || /[\x00-\x1f]/.test(path))
    || !value.ai || typeof value.ai !== "object" || Array.isArray(value.ai)) throw Error("SCOPED_CONFIG_INVALID");
  return structuredClone(value);
}
export function checkedProvenanceCatalogue(value: any) {
  if (!exact(value, ["schemaVersion", "artifacts"]) || value.schemaVersion !== "mcpshield.scoped-provenance-catalogue.v1" || !Array.isArray(value.artifacts)
    || value.artifacts.length > 128 || Buffer.byteLength(JSON.stringify(value)) > 512 * 1024) throw Error("SCOPED_CATALOGUE_INVALID");
  const artifacts = value.artifacts.map((item: any) => checkedScopedProvenance(item, item?.sourceArtifactDigest));
  if (new Set(artifacts.map((item: any) => item.sourceArtifactDigest)).size !== artifacts.length) throw Error("SCOPED_CATALOGUE_INVALID");
  return artifacts as Record<string, any>[];
}
export async function loadScopedProvenance(filename: string | undefined, sourceArtifactDigest: string) {
  // No cached approvals: empty/replaced local files revoke eligibility immediately.
  try {
    if (!filename || !isAbsolute(filename)) throw Error();
    const file = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const stat = await file.stat(); if (!stat.isFile() || stat.size < 1 || stat.size > 512 * 1024) throw Error();
      const bytes = Buffer.alloc(stat.size + 1); let offset = 0;
      while (offset < bytes.length) { const read = await file.read(bytes, offset, bytes.length - offset); if (!read.bytesRead) break; offset += read.bytesRead; }
      if (offset !== stat.size) throw Error();
      const catalogue = checkedProvenanceCatalogue(JSON.parse(bytes.subarray(0, offset).toString("utf8")));
      return checkedScopedProvenance(catalogue.find(item => item.sourceArtifactDigest === sourceArtifactDigest), sourceArtifactDigest);
    } finally { await file.close(); }
  } catch { throw Error("SCOPED_OPERATOR_PROVENANCE_REQUIRED"); }
}
export function scopedMetadata(policy: any) {
  if (policy?.profile !== SCOPED_NODE_PROFILE || !validateScopedReviewPolicy(policy.semantic)) return {};
  return { semanticEvidenceMode: policy.semantic.evidenceMode, providerQuality: "PROVIDER_QUALITY_NOT_MEASURED" };
}
export async function scopedPreparationContext(options: ControlOptions, tenant: string, policy: any, source: Record<string, any>) {
  if (policy?.profile !== SCOPED_NODE_PROFILE || !validateScopedReviewPolicy(policy.semantic) || !options.preparedRuntime || !options.scopedPrepared) throw Error("SCOPED_CONFIG_REQUIRED");
  const config = checkedScopedConfig(options.scopedPrepared);
  const sourceProvenance = await loadScopedProvenance(Object.hasOwn(config.provenancePaths, tenant) ? config.provenancePaths[tenant] : undefined, source?.artifactDigest);
  let resolved, sourceBudget;
  try {
    if (!source?.artifactDir || !isAbsolute(source.artifactDir)) throw Error("SCOPED_SOURCE_UNAVAILABLE");
    resolved = await resolveArtifact({ sourceType: "local", locator: source.artifactDir });
    if (exactReleaseIdentity(resolved).releaseId !== source.releaseId || resolved.artifactDigest !== source.artifactDigest) throw Error("SCOPED_SOURCE_IDENTITY_MISMATCH");
    const sourceBytes = resolved.metadata?.sizeBytes;
    if (!Number.isSafeInteger(sourceBytes) || sourceBytes < 0 || sourceBytes > policy.maxArtifactBytes) throw Error("SCOPED_SOURCE_BUDGET_EXCEEDED");
    sourceBudget = { sourceArtifactDigest: source.artifactDigest, sourceBytes };
  } catch (error: any) {
    throw Error(/^SCOPED_[A-Z0-9_]+$/.test(error?.message ?? "") ? error.message : "SCOPED_SOURCE_UNAVAILABLE");
  } finally { await resolved?.cleanup?.(); }
  const trusted = preparedTrust(options.preparedRuntime);
  const executionPolicy = scopedPreparedExecutionPolicy({ collectorDigest: trusted.collectorDigest, observerDigest: trusted.observerDigest,
    egressAllowHosts: ["mail-api.local", "exfil-sink.local"] }, policy.semantic);
  if (config.ai.evidenceMode !== policy.semantic.evidenceMode) throw Error("SCOPED_EVIDENCE_MODE_MISMATCH");
  const ai = checkedScopedAi(config.ai, policy.semantic);
  // A private commitment detects worker-local changes without persisting endpoints,
  // credentials or local paths. The scanner repeats validation at the actual tier.
  return { trusted, scopedReview: { executionPolicy, sourceProvenance }, ai, sourceBudget,
    frozen: { ...trusted, scopedReview: { executionPolicy, sourceProvenance }, sourceBudget, aiConfigHash: hash(config.ai) } };
}
