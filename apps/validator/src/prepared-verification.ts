import { mkdir, appendFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { hash } from "../../api/src/control-plane.js";
import { policyVerdict, preparedPolicy } from "../../api/src/control-policy.js";
import { checkedPreparedEvidence } from "../../api/src/prepared-evidence.js";
import { inspectPreparedRuntime, type PreparedConfig } from "../../api/src/prepared-config.js";
import { checkedServiceUrl } from "../../../packages/contracts-sdk/src/transport.js";
// @ts-expect-error Shared ESM evidence bundle helper.
import { createEvidenceBundle } from "../../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared actual prepared runtime scanner.
import { scanPreparedRuntime } from "../../../services/scanner/src/prepared-scan.mjs";

export interface PreparedValidatorAi {
  allowRemoteAi: true; provider: "custom" | "openai"; model?: string; url?: string; token?: string; timeoutMs?: number;
}
export function checkedPreparedValidatorAi(ai?: PreparedValidatorAi) {
  if (!ai || ai.allowRemoteAi !== true || Object.keys(ai).some((key) => !["allowRemoteAi", "provider", "model", "url", "token", "timeoutMs"].includes(key))
    || !["custom", "openai"].includes(ai.provider) || ai.provider === "openai" && (!ai.model || !ai.token)
    || ai.provider === "custom" && !ai.url || ai.timeoutMs !== undefined && (!Number.isSafeInteger(ai.timeoutMs) || ai.timeoutMs < 100 || ai.timeoutMs > 120000)) throw new Error("PREPARED_VALIDATOR_EXPLICIT_AI_REQUIRED");
  if (ai.url) checkedServiceUrl(ai.url);
  return ai;
}
function deterministicScopes(result: any) {
  const scopes = result.findings.filter((finding: any) => finding.deterministic && finding.stage === "SANDBOX" && ["HIGH", "CRITICAL"].includes(finding.severity))
    .map((finding: any) => ({ code: finding.code, stage: finding.stage, severity: finding.severity, observer: finding.evidence?.observer ?? "FULL_TOOL_SURFACE_COMPARISON" }));
  // Independent plans/canaries can observe the same violation more than once; compare scopes, not incidental counts.
  return [...new Map(scopes.map((scope: any) => [hash(scope), scope])).entries()].sort(([a], [b]) => String(a).localeCompare(String(b))).map(([, scope]) => scope);
}
export function comparePreparedScans(original: any, independent: any, policy: any, trusted: Record<string, any>) {
  if (policy.profile !== preparedPolicy.profile) throw new Error("PREPARED_POLICY_REQUIRED");
  const first = checkedPreparedEvidence(original.bundle), second = checkedPreparedEvidence(independent.bundle);
  if (hash(first.binding) !== hash(second.binding) || hash(first.source) !== hash(second.source)
    || original.result.scanId === independent.result.scanId) throw new Error("INDEPENDENT_SCAN_IDENTITY_MISMATCH");
  const originalVerdict = policyVerdict(original.bundle, original.result, policy, trusted), independentVerdict = policyVerdict(independent.bundle, independent.result, policy, trusted);
  if (originalVerdict === "ABSTAIN" || originalVerdict !== independentVerdict
    || hash(deterministicScopes(original.result)) !== hash(deterministicScopes(independent.result))) throw new Error("INDEPENDENT_SCAN_DID_NOT_CONFIRM");
  return { verdict: originalVerdict, originalReportRoot: original.bundle.manifest.root, independentReportRoot: independent.bundle.manifest.root,
    findingScopeHash: hash(deterministicScopes(independent.result)) };
}
export async function independentlyScanPrepared(original: any, policy: any, config: PreparedConfig, ai?: PreparedValidatorAi) {
  const localAi = checkedPreparedValidatorAi(ai), { binding, source } = checkedPreparedEvidence(original.bundle);
  const trusted = await inspectPreparedRuntime(binding, config);
  if (policyVerdict(original.bundle, original.result, policy, trusted) === "ABSTAIN") throw new Error("INDEPENDENT_ORIGINAL_NOT_APPROVABLE");
  // Fresh local AI plan + independent analyzer/critic and actual Docker runs. No API probe/model/url or advertised execution flag is accepted.
  const result = await scanPreparedRuntime({ descriptor: binding.descriptor, expectedDescriptorDigest: binding.descriptorDigest,
    sourceReleaseId: binding.sourceReleaseId, releaseId: original.result.releaseId, scanId: randomUUID(), ai: localAi, trusted });
  if (!result.binding || !result.result || !result.bundle) throw new Error("INDEPENDENT_SCAN_INCOMPLETE");
  const bundle = createEvidenceBundle({ ...Object.fromEntries(Object.entries(result.bundle.files).map(([path, content]) => [path, JSON.parse(content as string)])),
    "prepared/source-identity.json": source });
  const independent = { result: result.result, bundle };
  return { trusted, independent, comparison: comparePreparedScans(original, independent, policy, trusted) };
}
export async function recordPreparedVerification(path: string, fields: { chainId: number; registryContract: string; validator: string; releaseId: string; policyHash: string },
  comparison: ReturnType<typeof comparePreparedScans>) {
  const receipt = { schemaVersion: "mcpshield.independent-scan-receipt.v1", verificationId: randomUUID(), ...fields, ...comparison,
    verifiedAt: new Date().toISOString(), state: "LOCAL_VERIFICATION_ONLY" };
  // Digest-only local audit receipt; no source bytes, tool data, provider response, credentials or private key.
  const target = resolve(path); await mkdir(dirname(target), { recursive: true });
  await appendFile(target, `${JSON.stringify(receipt)}\n`, { mode: 0o600 });
  return receipt;
}
