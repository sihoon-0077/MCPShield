import { canonicalJson } from './canonical-json.mjs';

export const SCOPED_DISCLOSURE_POLICY = 'SCOPED_PROVIDER_REVIEW_V1';
export const SCOPED_NODE_PROFILE = 'restricted-node-docker-v2';
export const SCOPED_OCI_PROFILE = 'restricted-oci-offline-v2';
export const SCOPED_INPUT_SCHEMA = 'mcpshield.scoped-semantic-input.v2';
export const SCOPED_PROOF_SCHEMA = 'mcpshield.scoped-disclosure-proof.v2';
export const SCOPED_REVIEW_SCHEMA = 'mcpshield.scoped-semantic-review.v2';
export const SCOPED_BASELINE_INPUT_SCHEMA = 'mcpshield.scoped-semantic-input.v2.1';
export const SCOPED_BASELINE_PROOF_SCHEMA = 'mcpshield.scoped-disclosure-proof.v2.1';
export const SCOPED_BASELINE_REVIEW_SCHEMA = 'mcpshield.scoped-semantic-review.v2.1';
export const SCOPED_EVIDENCE_MODES = Object.freeze(['PROVIDER_EXECUTION', 'LOCAL_CONTRACT_TEST']);
export const SCOPED_LIMITS = Object.freeze({ inputBytes: 64 * 1024, snippetChars: 32 * 1024, fileSnippetChars: 2048,
  fileFraction: 0.25, localSourceBytes: 8 * 1024 * 1024, localFiles: 50_000, snippets: 64, disclosureWork: 8_000_000 });
export const SCOPED_ROLES = Object.freeze(['analyzer', 'critic', 'probe']);

// Fixed policy commitment only, not an approval and not a provider-quality claim.
// A consumer must match the whole object, never just accept a profile string.
export function scopedReviewPolicy(evidenceMode) {
  if (!SCOPED_EVIDENCE_MODES.includes(evidenceMode)) throw Error('SCOPED_EVIDENCE_MODE_INVALID');
  return { schemaVersion: 'mcpshield.scoped-review-policy.v1', disclosurePolicy: SCOPED_DISCLOSURE_POLICY,
    tierPolicy: 'LOCAL_RISK_TIERED_V1', evidenceMode, limits: { ...SCOPED_LIMITS },
    roles: { required: [...SCOPED_ROLES], tier3Additional: ['analyzer2'], critic: 'SEPARATE_BLIND_CONTEXT' },
    privacyScope: { sourceProvenance: 'OPERATOR_LOCAL_CODE_ARTIFACT_REQUIRED', wholeSource: 'FORBIDDEN',
      runtimeValues: 'HASH_AND_COUNT_ONLY', customerData: 'FORBIDDEN_BY_OPERATOR_SCOPE_NOT_AUTOMATICALLY_PROVEN',
      selection: 'METADATA_AND_BOUNDED_REDACTED_SECURITY_RISK_DIFF', unknownClassification: 'ABSTAIN',
      arbitraryEncodedOrRewrittenData: 'NOT_PROVEN_SAFE', providerQuality: 'PROVIDER_QUALITY_NOT_MEASURED' } };
}

export function validateScopedReviewPolicy(value) {
  try { return canonicalJson(value) === canonicalJson(scopedReviewPolicy(value.evidenceMode)); }
  catch { return false; }
}

// Explicit opt-in. Never change the bytes/defaults of the v2.0 commitment above.
export function scopedBaselineReviewPolicy(evidenceMode) {
  const previous = scopedReviewPolicy(evidenceMode);
  return { ...previous, schemaVersion: 'mcpshield.scoped-review-policy.v2.1', tierPolicy: 'LOCAL_RISK_TIERED_BASELINE_V1',
    privacyScope: { ...previous.privacyScope, selection: 'ALL_CURRENT_RISK_PLUS_PINNED_BASELINE_DIFF' },
    baseline: { selection: 'EXPLICIT_PREPARED_RELEASE_OR_NULL', authority: 'SAME_TOOL_OPERATOR_REACQUIRED_SOURCE_AND_RUNTIME',
      currentCoverage: 'NO_BASELINE_EXEMPTION', acquisition: 'IMAGE_EXPORT_AND_ISOLATED_TOOLS_LIST',
      approvalInheritance: 'NONE', unverifiable: 'ABSTAIN' } };
}
export function validateScopedBaselineReviewPolicy(value) {
  try { return canonicalJson(value) === canonicalJson(scopedBaselineReviewPolicy(value.evidenceMode)); }
  catch { return false; }
}

// This object must come from the operator's exact-source catalogue, never a
// package field or public API body. Its bytes bind the declaration, not its truth;
// an independent validator must use its own catalogue and source acquisition.
export function checkedScopedProvenance(value, sourceArtifactDigest) {
  if (!/^sha256:[a-f0-9]{64}$/.test(sourceArtifactDigest) || !value ||
    Object.keys(value).sort().join() !== 'authority,contentClass,schemaVersion,sourceArtifactDigest' ||
    value.schemaVersion !== 'mcpshield.operator-code-artifact.v1' || value.authority !== 'OPERATOR_LOCAL_CATALOG' ||
    value.contentClass !== 'CODE_ARTIFACT_NO_CUSTOMER_DATA' || value.sourceArtifactDigest !== sourceArtifactDigest) {
    throw Error('SCOPED_OPERATOR_PROVENANCE_REQUIRED');
  }
  return { ...value };
}
