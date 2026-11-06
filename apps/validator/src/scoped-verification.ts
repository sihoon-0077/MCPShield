import { isAbsolute } from "node:path";
import { hash } from "../../api/src/control-plane.js";
import { checkedScopedAi, loadScopedAuthority, publisherEvidence, type ScopedAi } from "../../api/src/scoped-config.js";
import { sourceIdentity } from "../../api/src/preparation-control.js";
import { loadValidatorSources } from "./source-verification.js";
import { validPolicy, isScopedBaselinePolicy } from "../../api/src/control-policy.js";
import { inspectPreparedRuntime, type PreparedConfig } from "../../api/src/prepared-config.js";
// @ts-expect-error Exact baseline commitment and independent authority; no report self-certification.
import { scopedBaselineCommitment, checkedScopedBaselineAuthority, SCOPED_BASELINE_TRUST_FIELDS } from "../../../services/scanner/src/scoped-baseline.mjs";
// @ts-expect-error Shared immutable resolver; never take a locator from the API.
import { resolveArtifact } from "../../../services/resolver/src/resolver.mjs";
// @ts-expect-error Shared frozen profile identity.
import { SCOPED_NODE_PROFILE } from "../../../services/scanner/src/scoped-policy.mjs";
import { exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2.js";

export interface ScopedValidatorConfig { provenancePath: string; sourcesPath: string; ai: ScopedAi }
export function checkedScopedValidatorConfig(value: any): ScopedValidatorConfig {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join() !== "ai,provenancePath,sourcesPath"
    || [value.provenancePath, value.sourcesPath].some(path => typeof path !== "string" || path.length > 4096 || !isAbsolute(path) || /[\x00-\x1f]/.test(path))
    || !value.ai || typeof value.ai !== "object" || Array.isArray(value.ai)) throw Error("SCOPED_VALIDATOR_CONFIG_REQUIRED");
  return structuredClone(value);
}
export async function checkedScopedSource(policy: any, binding: any, expectedSource: any, options?: ScopedValidatorConfig, baselineDocument?: any): Promise<Record<string, any>> {
  if (!validPolicy(policy) || policy.profile !== SCOPED_NODE_PROFILE || hash(policy.semantic) !== hash(binding.executionPolicy.semantic)) throw Error("SCOPED_POLICY_REQUIRED");
  const config = checkedScopedValidatorConfig(options);
  const catalogue = await loadValidatorSources(config.sourcesPath);
  const current = await acquireScopedSource(policy, binding, expectedSource, config, catalogue);
  if (!isScopedBaselinePolicy(policy)) return current;
  // The key is derived from the checked runtime binding, never the scan's advertised ID.
  const releaseId = exactReleaseIdentity({ toolId: expectedSource.toolId, artifactDigest: binding.artifactDigest,
    manifestDigest: binding.manifestDigest, toolSurfaceHash: binding.toolSurfaceHash }).releaseId;
  if (!catalogue.baselines || !Object.hasOwn(catalogue.baselines, releaseId)) throw Error("SCOPED_VALIDATOR_BASELINE_REQUIRED");
  const selected = catalogue.baselines[releaseId], baseline = baselineDocument === null ? null : baselineDocument?.selection;
  const scopedReview = { executionPolicy: binding.executionPolicy, sourceIdentity: current.sourceIdentity, sourceProvenance: current.sourceProvenance, baseline };
  const commitment = scopedBaselineCommitment(scopedReview);
  if (selected !== (commitment?.releaseId ?? null)) throw Error("SCOPED_VALIDATOR_BASELINE_MISMATCH");
  const previous = baseline === null ? null : await acquireScopedSource(policy, baseline.binding, baseline.sourceIdentity, config, catalogue);
  if (previous && hash(previous.sourceProvenance) !== hash(baseline.sourceProvenance)) throw Error("SCOPED_VALIDATOR_BASELINE_MISMATCH");
  return { ...current, scopedReview, baselineSource: previous,
    configHash: hash({ current: current.configHash, baselineReleaseId: selected, baselineConfigHash: previous?.configHash ?? null, baseline }) };
}
async function acquireScopedSource(policy: any, binding: any, expectedSource: any, config: ScopedValidatorConfig, catalogue: Awaited<ReturnType<typeof loadValidatorSources>>) {
  const { sourceProvenance, demoPublisher } = await loadScopedAuthority(config.provenancePath, binding.sourceArtifactDigest);
  const selected = catalogue.sources.find(item => item.releaseId === binding.sourceReleaseId);
  if (!selected || selected.sourceType === "oci") throw Error("SCOPED_VALIDATOR_SOURCE_REQUIRED");
  let resolved;
  try {
    resolved = await resolveArtifact({ sourceType: selected.sourceType, locator: selected.locator }, { demoPublisher });
    const acquired = sourceIdentity({ ...resolved, ...exactReleaseIdentity(resolved), artifactDigest: resolved.artifactDigest,
      manifestDigest: resolved.manifestDigest, toolSurfaceHash: resolved.toolSurfaceHash });
    if (hash(acquired) !== hash(expectedSource) || acquired.releaseId !== binding.sourceReleaseId || acquired.artifactDigest !== binding.sourceArtifactDigest
      || (resolved.metadata?.archiveDigest ?? resolved.artifactDigest) !== binding.descriptor.sourceDigest) throw Error("SCOPED_VALIDATOR_SOURCE_MISMATCH");
    const sourceBytes = resolved.metadata?.expandedBytes ?? resolved.metadata?.sizeBytes;
    if (!Number.isSafeInteger(sourceBytes) || sourceBytes < 0 || sourceBytes > policy.maxArtifactBytes) throw Error("SCOPED_SOURCE_BUDGET_EXCEEDED");
    const sourceBudget = { sourceArtifactDigest: acquired.artifactDigest, sourceBytes };
    const ai = checkedScopedAi(config.ai, policy.semantic);
    const publisher = publisherEvidence(resolved, demoPublisher);
    const configHash = hash({ selected, sourceProvenance, sourceBudget, ai, ...(publisher ? { publisher, publisherTrustHash: hash(demoPublisher) } : {}) });
    return { sourceProvenance, ai, configHash, sourceIdentity: acquired, sourceBudget, publisher };
  } catch (error: any) {
    if (/^SCOPED_[A-Z0-9_]+$/.test(error?.message ?? "")) throw error;
    if (/^DEMO_PUBLISHER_/.test(error?.message ?? "")) throw Error("SCOPED_PUBLISHER_SIGNATURE_INVALID");
    throw Error("SCOPED_VALIDATOR_SOURCE_UNAVAILABLE");
  } finally { await resolved?.cleanup?.(); }
}
export async function inspectScopedValidatorBaseline(scoped: Record<string, any>, config: PreparedConfig) {
  const selection = scoped.scopedReview?.baseline;
  if (selection === undefined) return undefined;
  if (selection === null) return null;
  const actual = await inspectPreparedRuntime(selection.binding, config);
  return refreshedScopedBaseline(scoped, actual);
}
export function refreshedScopedBaseline(scoped: Record<string, any>, runtime: any) {
  const selection = scoped.scopedReview?.baseline;
  if (selection === null) { if (runtime !== null) throw Error("SCOPED_BASELINE_AUTHORITY_MISMATCH"); return null; }
  if (!selection || !runtime) throw Error("SCOPED_BASELINE_AUTHORITY_MISMATCH");
  const trusted = { ...Object.fromEntries(SCOPED_BASELINE_TRUST_FIELDS.slice(0, 8).map((key: string) => [key, runtime[key]])),
    releaseId: selection.releaseId, sourceIdentity: scoped.baselineSource.sourceIdentity, sourceProvenance: scoped.baselineSource.sourceProvenance,
    sourceBudget: scoped.baselineSource.sourceBudget, publisher: scoped.baselineSource.publisher ?? null };
  checkedScopedBaselineAuthority(scoped.scopedReview, trusted);
  return trusted;
}
