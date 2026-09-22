import { randomUUID } from "node:crypto";
import { hash } from "../../api/src/control-plane.js";
import { assertRuntimeBudget, ociPolicy, policyVerdict, validPolicy } from "../../api/src/control-policy.js";
import { checkedOciEvidence } from "../../api/src/prepared-evidence.js";
import { checkedOciConfig, inspectOciRuntime, type OciConfig } from "../../api/src/oci-config.js";
import { checkedPreparedValidatorAi, deterministicScopes, type PreparedValidatorAi } from "./prepared-verification.js";
// @ts-expect-error Shared evidence commitments; no API-provided verification hook.
import { createEvidenceBundle, verifyEvidenceBundle } from "../../../services/scanner/src/evidence.mjs";
// @ts-expect-error Actual local OCI review and sandbox, not a supplied execution flag.
import { scanOciRuntime } from "../../../services/scanner/src/oci-scan.mjs";

export function compareOciScans(original: any, independent: any, policy: any, trusted: Record<string, any>) {
  if (!validPolicy(policy) || policy.profile !== ociPolicy.profile) throw new Error("OCI_POLICY_REQUIRED");
  const first = checkedOciEvidence(original.bundle), second = checkedOciEvidence(independent.bundle);
  assertRuntimeBudget(first.source, policy, first.binding.descriptor);
  if (hash(first.binding) !== hash(second.binding) || hash(first.source) !== hash(second.source)
    || original.result.scanId === independent.result.scanId) throw new Error("INDEPENDENT_SCAN_IDENTITY_MISMATCH");
  const verdict = policyVerdict(original.bundle, original.result, policy, trusted), checked = policyVerdict(independent.bundle, independent.result, policy, trusted);
  const scopes = deterministicScopes(independent.result, true);
  if (verdict === "ABSTAIN" || verdict !== checked || hash(deterministicScopes(original.result, true)) !== hash(scopes)) throw new Error("INDEPENDENT_SCAN_DID_NOT_CONFIRM");
  return { verdict, originalReportRoot: original.bundle.manifest.root, independentReportRoot: independent.bundle.manifest.root, findingScopeHash: hash(scopes),
    profile: ociPolicy.profile, semanticEvidenceMode: "LOCAL_CONTRACT_TEST", providerQuality: "PROVIDER_QUALITY_NOT_MEASURED" };
}

export async function independentlyScanOci(original: any, policy: any, config: OciConfig, ai?: PreparedValidatorAi) {
  const local = checkedOciConfig(config), localAi = checkedPreparedValidatorAi(ai);
  if (localAi.disclosurePolicy !== "LOCAL_CONTRACT_TEST") throw new Error("OCI_VALIDATOR_LOCAL_CONTRACT_REQUIRED");
  if (!validPolicy(policy) || policy.profile !== ociPolicy.profile || !verifyEvidenceBundle(original.bundle, original.bundle?.manifest?.root)) throw new Error("OCI_POLICY_OR_EVIDENCE_INVALID");
  const { binding, source } = checkedOciEvidence(original.bundle);
  assertRuntimeBudget(source, policy, binding.descriptor);
  if (!["PASSED", "FAILED"].includes(original.result?.scanStatus)) throw new Error("INDEPENDENT_ORIGINAL_NOT_APPROVABLE");
  const trusted = await inspectOciRuntime(binding, local);
  if (policyVerdict(original.bundle, original.result, policy, trusted) === "ABSTAIN") throw new Error("INDEPENDENT_ORIGINAL_NOT_APPROVABLE");
  // Own immutable Docker/base/DB bytes, fresh generated synthetic probes and own local
  // analyzer/critic are mandatory. Never replay API-supplied probe plans or model settings.
  const output = await scanOciRuntime({ descriptor: binding.descriptor, expectedDescriptorDigest: binding.descriptorDigest, sourceReleaseId: binding.sourceReleaseId,
    releaseId: original.result.releaseId, scanId: randomUUID(), trust: local, ai: localAi });
  if (!output.binding || !output.result || !output.bundle) throw new Error("INDEPENDENT_SCAN_INCOMPLETE");
  const bundle = createEvidenceBundle({ ...Object.fromEntries(Object.entries(output.bundle.files).map(([path, content]) => [path, JSON.parse(content as string)])),
    "prepared/source-identity.json": source });
  const independent = { result: output.result, bundle };
  return { trusted, independent, comparison: compareOciScans(original, independent, policy, trusted) };
}
