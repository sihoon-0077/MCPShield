import { canonicalJson, verifyEvidenceBundle } from './evidence.mjs';
import { validateOciReleaseBinding } from './oci-binding.mjs';
import { reconstructOciSemanticSources, verifyOciSemanticReview } from './oci-sources.mjs';
import { assessTrivyDocuments, checkedTrivyDatabaseMetadata } from './oci-trivy.mjs';
import { validateProbePlan } from './probes.mjs';
import { toolSurfaceHash } from './tool-surface.mjs';
import { assertScanResult } from './schema.mjs';
import { redactEvidenceDocument } from './redaction.mjs';
import { hashOciRuntimeDescriptor, ociHash } from '../../resolver/src/oci-runtime-descriptor.mjs';

const same = (a, b) => canonicalJson(a) === canonicalJson(b);
const sha = /^sha256:[a-f0-9]{64}$/;
export const OCI_POLICY_CHECKS = Object.freeze(['runtimeIdentityVerified', 'originalSourceVerified', 'trustedBaseVerified',
  'sourceClassificationComplete', 'vulnerabilityAndSbomComplete', 'semanticComplete', 'independentCriticComplete', 'semanticNoUnresolvedRisk',
  'discoveryComplete', 'toolSurfaceStable', 'normalProbeComplete', 'adversarialProbeComplete', 'normalToolCallsSucceeded', 'adversarialToolCallsSucceeded']);

// Reconstruct effects, never accept advertised observation.findings as authority.
export function ociSandboxFindings(observation) {
  const effects = [];
  // Canonical JSON sorts object keys; evidence arrays must not depend on the
  // insertion order before/after a Merkle serialization round trip.
  for (const stage of ['discovery', 'normal', 'adversarial']) {
    const step = observation.steps?.[stage];
    if (!step) continue;
    if (step.canaryHashes?.length) effects.push({ code: 'CANARY_EXFILTRATION', severity: 'CRITICAL', stage,
      observer: 'INDEPENDENT_SYNTHETIC_SINK', canaryHashes: step.canaryHashes });
    if (step.undeclaredEgress === true) effects.push({ code: 'UNDECLARED_EGRESS', severity: 'HIGH', stage, observer: 'INDEPENDENT_SYNTHETIC_PROXY' });
    if (step.mcp?.complete && step.mcp.toolSurfaceHash !== observation.steps.discovery?.mcp.toolSurfaceHash)
      effects.push({ code: 'TOOL_SURFACE_CHANGED', severity: 'HIGH', stage });
  }
  return redactEvidenceDocument(effects.map(({ code, severity, stage, observer, canaryHashes }) => ({ code, severity, stage: 'SANDBOX',
    deterministic: true, message: 'The isolated external OCI collector observed a synthetic scope violation.',
    evidence: { observationStage: stage, ...(observer ? { observer } : {}), ...(canaryHashes ? { canaryHashes } : {}) } })));
}

// Pure, bounded-profile evidence assessment, NOT an execution attestation.
// trusted must come from validator-local readTrustedOciRuntime, never the API.
// Signing also requires a fresh local full scan and deterministic-scope comparison.
export function assessOciPolicy(bundle, result, binding, trusted) {
  const checks = Object.fromEntries(OCI_POLICY_CHECKS.map((name) => [name, false]));
  const outcome = (verdict, issues = []) => ({ profile: 'restricted-oci-offline-v1', verdict, checks, issues,
    semanticEvidenceMode: 'LOCAL_CONTRACT_TEST', providerQuality: 'PROVIDER_QUALITY_NOT_MEASURED',
    fullBehaviorCoverage: false, scope: 'RESTRICTED_PACKAGED_DATA_OR_COMPUTE_NOT_NATIVE_SAFETY_PROOF' });
  const abstain = (code) => outcome('ABSTAIN', [code]);
  try {
    assertScanResult(result);
    if (!verifyEvidenceBundle(bundle, bundle.manifest.root) || !validateOciReleaseBinding(binding) ||
      binding.executionPolicy.profile !== 'restricted-oci-offline-v1') return abstain('OCI_EVIDENCE_OR_BINDING_INVALID');
    if (!trusted || !same(trusted.anchors, binding.executionPolicy.trust) || trusted.descriptorDigest !== binding.descriptorDigest ||
      trusted.finalImageDigest !== binding.finalImageDigest || trusted.rootfsDigest !== binding.descriptor.rootfsDigest ||
      !same(trusted.platform, binding.platform) || trusted.observationPolicy.collectorDigest !== trusted.anchors.observerDigest ||
      trusted.observationPolicy.sinkCodeDigest !== trusted.anchors.sinkCodeDigest || trusted.observationPolicy.sinkImageDigest !== trusted.anchors.sinkImageDigest)
      return abstain('OCI_LOCAL_TRUST_MISMATCH');
    const read = (path) => JSON.parse(bundle.files[path]);
    const report = read('report.json'), observation = read('oci/observation.json'), tools = read('runtime/tools.json');
    if (!Array.isArray(tools) || !tools.length || tools.length > 128 || new Set(tools.map((tool) => tool.name)).size !== tools.length)
      return abstain('OCI_TOOL_SURFACE_INVALID');
    const preparationDigest = hashOciRuntimeDescriptor({ ...binding.descriptor, stage: 'IMPORTED', toolSurfaceHash: null });
    if (!same(read('oci/binding.json'), binding) || !same(read('runtime/oci-descriptor.json'), binding.descriptor) ||
      !same(read('runtime/execution-policy.json'), binding.executionPolicy) || !same(read('runtime/observation-policy.json'), trusted.observationPolicy) ||
      report.scope !== 'RESTRICTED_OCI_OFFLINE_V1' || Object.keys(result).some((key) => !same(report[key], result[key])) ||
      result.source !== 'LIVE' || result.artifactDigest !== binding.artifactDigest || result.toolSurfaceHash !== binding.toolSurfaceHash ||
      result.evidenceHash !== '0x' + ociHash(canonicalJson(result.findings)).slice(7) ||
      toolSurfaceHash(tools) !== binding.toolSurfaceHash || observation.profile !== 'oci-container-v1' ||
      observation.preparationDescriptorDigest !== preparationDigest || observation.observedDescriptorDigest !== binding.descriptorDigest ||
      observation.executionPolicyDigest !== ociHash(canonicalJson(trusted.observationPolicy))) return abstain('OCI_REPORT_IDENTITY_MISMATCH');
    const steps = observation.steps;
    const validStep = (step) => step?.source === 'LIVE_DOCKER_EXTERNAL_MCP_CLIENT' && step.runtimeDigest === preparationDigest &&
      Array.isArray(step.canaryHashes) && step.canaryHashes.length <= 8 && step.canaryHashes.every((hash) => /^[a-f0-9]{64}$/.test(hash)) &&
      new Set(step.canaryHashes).size === step.canaryHashes.length && typeof step.undeclaredEgress === 'boolean' && typeof step.eventBodyLimit === 'boolean' &&
      Number.isSafeInteger(step.eventCount) && step.eventCount >= step.canaryHashes.length && step.eventCount <= 1024 && step.mcp;
    checks.runtimeIdentityVerified = Boolean(observation.source === 'LIVE_DOCKER_EXTERNAL_MCP_CLIENT' &&
      Object.keys(steps).length && Object.keys(steps).every((stage) => ['discovery', 'normal', 'adversarial'].includes(stage)) && Object.values(steps).every(validStep));
    if (!checks.runtimeIdentityVerified) return abstain('OCI_RUNTIME_OBSERVATION_UNBOUND');
    const sandbox = ociSandboxFindings(observation);
    if (!same(result.findings.filter(({ stage }) => stage === 'SANDBOX'), sandbox)) return abstain('OCI_EFFECT_FINDINGS_MISMATCH');
    if (sandbox.length && result.scanStatus === 'FAILED') return outcome('FAIL');
    const complete = (step) => validStep(step) && step.mcp.complete === true && !step.eventBodyLimit &&
      Number.isSafeInteger(step.mcp.pages) && step.mcp.pages >= 1 && step.mcp.pages <= 32 &&
      Number.isSafeInteger(step.mcp.receivedBytes) && step.mcp.receivedBytes > 0 && step.mcp.receivedBytes <= 256 * 1024 &&
      typeof step.mcp.protocolVersion === 'string' && Array.isArray(step.mcp.callResults);
    checks.discoveryComplete = Boolean(complete(steps.discovery) && steps.discovery.mcp.callResults.length === 0);
    checks.toolSurfaceStable = checks.discoveryComplete && ['discovery', 'normal', 'adversarial'].every((stage) => steps[stage]?.mcp.toolSurfaceHash === binding.toolSurfaceHash);
    const plan = validateProbePlan({ scenarios: observation.scenarios.map((scenario) => ({ scenarioId: scenario.scenarioId, kind: scenario.kind,
      goal: scenario.goal, toolName: scenario.toolCall.name, argumentsJson: canonicalJson(scenario.toolCall.arguments) })) }, tools);
    if (!same(plan.scenarios, observation.scenarios)) return abstain('OCI_PROBE_PLAN_INVALID');
    for (const [stage, kind] of [['normal', 'NORMAL'], ['adversarial', 'ADVERSARIAL']]) {
      const planned = plan.scenarios.filter((scenario) => scenario.kind === kind), calls = steps[stage]?.mcp.callResults;
      checks[`${stage}ProbeComplete`] = Boolean(complete(steps[stage]) && planned.length && calls.length === planned.length &&
        calls.every((call, index) => call.name === planned[index].toolCall.name && typeof call.isError === 'boolean' && sha.test(call.contentHash)));
      checks[`${stage}ToolCallsSucceeded`] = checks[`${stage}ProbeComplete`] && calls.every(({ isError }) => !isError);
    }
    const privateEvidence = read('oci/private-image-evidence.json');
    const reconstructed = reconstructOciSemanticSources(binding.descriptor, privateEvidence);
    checks.trustedBaseVerified = privateEvidence.catalogue.baseImageDigest === trusted.anchors.baseImageDigest &&
      privateEvidence.catalogue.catalogueDigest === trusted.anchors.baseCatalogueDigest &&
      (trusted.anchors.baseImageDigest !== binding.finalImageDigest || privateEvidence.catalogue.rootfsDigest === trusted.rootfsDigest);
    checks.originalSourceVerified = checks.trustedBaseVerified && privateEvidence.inventory.digest === trusted.rootfsDigest &&
      same(read('oci/source-reconstruction.json'), { semanticInputDigest: reconstructed.semanticInputDigest, sourceBytes: reconstructed.sourceBytes,
        coverage: reconstructed.coverage, structureDigest: ociHash(canonicalJson(reconstructed.structure)) });
    checks.sourceClassificationComplete = checks.originalSourceVerified && reconstructed.coverage.sourceClassificationComplete;
    const review = read('oci/image-review.json'), { reviewDigest, ...reviewBody } = review, vulnerability = review.vulnerability;
    if (reviewDigest !== ociHash(canonicalJson(reviewBody)) || review.image.finalImageDigest !== binding.finalImageDigest ||
      review.image.rootfsDigest !== trusted.rootfsDigest || review.image.descriptorDigest !== preparationDigest ||
      !same(review.coverage, reconstructed.coverage)) return abstain('OCI_IMAGE_REVIEW_MISMATCH');
    const targets = [...new Set([trusted.anchors.baseImageDigest, binding.finalImageDigest])];
    const documents = privateEvidence.trivy?.documents;
    if (privateEvidence.trivy?.access !== 'ENCRYPTED_OPERATOR_EVIDENCE_ONLY' || !Array.isArray(documents) ||
      documents.length !== targets.length || documents.some((document, index) => document.imageDigest !== targets[index] || !sha.test(document.archiveDigest)))
      return abstain('OCI_NATIVE_TRIVY_EVIDENCE_REQUIRED');
    const assessed = documents.map(({ report, sbom, imageDigest }) => assessTrivyDocuments(report, sbom, imageDigest));
    const metadata = checkedTrivyDatabaseMetadata({ Version: 2, UpdatedAt: trusted.database.updatedAt, NextUpdate: trusted.database.nextUpdate });
    checks.vulnerabilityAndSbomComplete = vulnerability.source === 'LIVE_OFFLINE_TRIVY_CONTAINER' &&
      vulnerability.toolImageDigest === trusted.anchors.trivyImageDigest && vulnerability.databaseDigest === trusted.anchors.databaseDigest &&
      same(vulnerability.database, { updatedAt: metadata.updatedAt, nextUpdate: metadata.nextUpdate, maxAgeHours: metadata.maxAgeHours }) &&
      same(vulnerability.images, assessed) && assessed.every(({ status, highCriticalCount, packageListComplete }) =>
        status === 'COMPLETE' && highCriticalCount === 0 && packageListComplete);
    Object.assign(checks, verifyOciSemanticReview({ semantic: read('semantic/reviews.json'), files: reconstructed.files, tools, releaseId: result.releaseId }));
    const approved = OCI_POLICY_CHECKS.every((name) => checks[name] === true) && result.scanStatus === 'PASSED' && !result.findings.length &&
      !observation.issues.length && !review.issues.length;
    return approved ? outcome('PASS') : abstain('OCI_REVIEW_OR_OBSERVATION_INCOMPLETE');
  } catch { return abstain('OCI_EVIDENCE_INCOMPLETE_OR_INVALID'); }
}
