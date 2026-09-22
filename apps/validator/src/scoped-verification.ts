import { isAbsolute } from "node:path";
import { hash } from "../../api/src/control-plane.js";
import { checkedScopedAi, loadScopedProvenance, type ScopedAi } from "../../api/src/scoped-config.js";
import { sourceIdentity } from "../../api/src/preparation-control.js";
import { loadValidatorSources } from "./source-verification.js";
import { validPolicy } from "../../api/src/control-policy.js";
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
export async function checkedScopedSource(policy: any, binding: any, expectedSource: any, options?: ScopedValidatorConfig) {
  if (!validPolicy(policy) || policy.profile !== SCOPED_NODE_PROFILE || hash(policy.semantic) !== hash(binding.executionPolicy.semantic)) throw Error("SCOPED_POLICY_REQUIRED");
  const config = checkedScopedValidatorConfig(options);
  const sourceProvenance = await loadScopedProvenance(config.provenancePath, binding.sourceArtifactDigest);
  const catalogue = await loadValidatorSources(config.sourcesPath);
  const selected = catalogue.sources.find(item => item.releaseId === binding.sourceReleaseId);
  if (!selected || selected.sourceType === "oci") throw Error("SCOPED_VALIDATOR_SOURCE_REQUIRED");
  let resolved;
  try {
    resolved = await resolveArtifact({ sourceType: selected.sourceType, locator: selected.locator });
    const acquired = sourceIdentity({ ...resolved, ...exactReleaseIdentity(resolved), artifactDigest: resolved.artifactDigest,
      manifestDigest: resolved.manifestDigest, toolSurfaceHash: resolved.toolSurfaceHash });
    if (hash(acquired) !== hash(expectedSource) || acquired.releaseId !== binding.sourceReleaseId || acquired.artifactDigest !== binding.sourceArtifactDigest
      || (resolved.metadata?.archiveDigest ?? resolved.artifactDigest) !== binding.descriptor.sourceDigest) throw Error("SCOPED_VALIDATOR_SOURCE_MISMATCH");
    const sourceBytes = resolved.metadata?.expandedBytes ?? resolved.metadata?.sizeBytes;
    if (!Number.isSafeInteger(sourceBytes) || sourceBytes < 0 || sourceBytes > policy.maxArtifactBytes) throw Error("SCOPED_SOURCE_BUDGET_EXCEEDED");
    const sourceBudget = { sourceArtifactDigest: acquired.artifactDigest, sourceBytes };
    const ai = checkedScopedAi(config.ai, policy.semantic);
    const configHash = hash({ selected, sourceProvenance, sourceBudget, ai });
    return { sourceProvenance, ai, configHash, sourceIdentity: acquired, sourceBudget };
  } catch (error: any) {
    if (/^SCOPED_[A-Z0-9_]+$/.test(error?.message ?? "")) throw error;
    throw Error("SCOPED_VALIDATOR_SOURCE_UNAVAILABLE");
  } finally { await resolved?.cleanup?.(); }
}
