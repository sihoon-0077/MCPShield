import { randomUUID } from 'node:crypto';
import { canonicalJson, createEvidenceBundle } from './evidence.mjs';
import { reviewOciImage } from './oci-review.mjs';
import { observeOciRuntime } from './oci-observer.mjs';
import { ociExecutionPolicy, createOciReleaseBinding } from './oci-binding.mjs';
import { reconstructOciSemanticSources, verifyOciSemanticReview } from './oci-sources.mjs';
import { reviewPreparedSemantics } from './prepared-review.mjs';
import { assertScanResult } from './schema.mjs';
import { redactEvidenceDocument } from './redaction.mjs';
import { importOciRuntime } from '../../resolver/src/oci-runtime.mjs';
import { hashOciRuntimeDescriptor, ociHash } from '../../resolver/src/oci-runtime-descriptor.mjs';

const sha = /^sha256:[a-f0-9]{64}$/;
const limitation = 'Restricted OCI image inspection and synthetic MCP observation; no filesystem syscall trace or arbitrary native binary safety proof. Independent OCI signing policy and Gateway binding are not yet enabled.';
const pending = ['OCI_INDEPENDENT_SIGNING_POLICY', 'OCI_GATEWAY_BINDING', 'OCI_FILESYSTEM_SYSCALL_OBSERVATION', 'OCI_STRUCTURE_POLICY_REVIEW'];

// No command/image/path is accepted from public API bodies. All runtime/trust
// input belongs to a server-owned job; raw source/tools live only in its encrypted bundle.
export async function scanOciRuntime({ descriptor, expectedDescriptorDigest, sourceReleaseId, releaseId, scanId = randomUUID(),
  trust, ai, probePlan, timeoutMs = 15_000, reviewTimeoutMs = 180_000 }) {
  if (hashOciRuntimeDescriptor(descriptor) !== expectedDescriptorDigest || !/^0x[a-f0-9]{64}$/.test(sourceReleaseId) ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(scanId) ||
    !/^.+@[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/.test(releaseId) ||
    ![trust?.baseImageDigest, trust?.trivyImageDigest, trust?.databaseDigest, trust?.sinkImageDigest].every((value) => sha.test(value)) ||
    !Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30_000 ||
    !Number.isSafeInteger(reviewTimeoutMs) || reviewTimeoutMs < 1 || reviewTimeoutMs > 180_000) throw Error('OCI_SCAN_INPUT_INVALID');
  const preparation = { ...descriptor, stage: 'IMPORTED', toolSurfaceHash: null }, preparationDigest = hashOciRuntimeDescriptor(preparation);
  const reviewed = await reviewOciImage({ descriptor: preparation, expectedDescriptorDigest: preparationDigest, trust, timeoutMs: reviewTimeoutMs });
  const { privateEvidence, ...reviewSummary } = reviewed;
  const observed = await observeOciRuntime({ descriptor: preparation, expectedDescriptorDigest: preparationDigest,
    sinkImageDigest: trust.sinkImageDigest, probePlan, ai: probePlan ? undefined : ai, timeoutMs });
  const documents = Object.fromEntries(Object.entries(observed.bundle.files).map(([path, value]) => [path, JSON.parse(value)]));
  const observationPolicy = documents['runtime/execution-policy.json'];
  documents['oci/observation.json'] = observed.report;
  documents['oci/image-review.json'] = reviewSummary;
  documents['runtime/observation-policy.json'] = observationPolicy;
  const issues = [...reviewed.issues, ...observed.report.issues];
  let reconstructed = null;
  if (privateEvidence) {
    try { reconstructed = reconstructOciSemanticSources(preparation, privateEvidence); }
    catch (error) { issues.push(/^OCI_[A-Z_]+$/.test(error.message) ? error.message : 'OCI_SOURCE_RECONSTRUCTION_FAILED'); }
    documents['oci/private-image-evidence.json'] = privateEvidence;
  } else issues.push('OCI_ORIGINAL_SOURCE_EVIDENCE_REQUIRED');
  const tools = documents['runtime/tools.json'];
  const semantic = reconstructed ? await reviewPreparedSemantics({ files: reconstructed.files, tools, releaseId, ai,
    profile: 'restricted-oci-offline-v1' }) : { semanticProfile: 'restricted-oci-offline-v1', reviews: [], complete: false,
    independentCriticComplete: false, noUnresolvedRisk: false, findings: [], issues: ['OCI_SEMANTIC_SOURCE_REQUIRED'] };
  issues.push(...semantic.issues, ...(reconstructed?.issues ?? []));
  documents['semantic/reviews.json'] = semantic;
  documents['oci/source-reconstruction.json'] = reconstructed ? { semanticInputDigest: reconstructed.semanticInputDigest,
    sourceBytes: reconstructed.sourceBytes, coverage: reconstructed.coverage, structureDigest: ociHash(canonicalJson(reconstructed.structure)) } : null;
  const semanticChecks = reconstructed ? verifyOciSemanticReview({ semantic, files: reconstructed.files, tools, releaseId }) :
    { semanticComplete: false, independentCriticComplete: false, semanticNoUnresolvedRisk: false };
  let binding = null;
  if (observed.observedDescriptor && reviewed.runtimeCatalogue) {
    const executionPolicy = ociExecutionPolicy({ baseImageDigest: trust.baseImageDigest,
      baseCatalogueDigest: reviewed.runtimeCatalogue.catalogueDigest, trivyImageDigest: trust.trivyImageDigest,
      databaseDigest: trust.databaseDigest, observerDigest: observationPolicy.collectorDigest,
      sinkImageDigest: trust.sinkImageDigest, sinkCodeDigest: observationPolicy.sinkCodeDigest });
    binding = createOciReleaseBinding({ sourceReleaseId, descriptor: observed.observedDescriptor, executionPolicy });
    if (descriptor.stage === 'OBSERVED' && binding.descriptorDigest !== expectedDescriptorDigest) issues.push('OCI_REGISTERED_SURFACE_CHANGED');
    documents['runtime/execution-policy.json'] = executionPolicy;
    documents['runtime/oci-descriptor.json'] = binding.descriptor;
    documents['oci/binding.json'] = binding;
  } else issues.push('OCI_DISCOVERY_AND_LOCAL_CATALOGUE_REQUIRED');
  const findings = redactEvidenceDocument([...semantic.findings, ...observed.report.findings.map(({ code, severity, stage, observer, canaryHashes }) => ({
    code, severity, stage: 'SANDBOX', deterministic: true, message: 'The isolated external OCI collector observed a synthetic scope violation.',
    evidence: { observationStage: stage, ...(observer ? { observer } : {}), ...(canaryHashes ? { canaryHashes } : {}) } }))]);
  const checks = { originalImageInventoryVerified: Boolean(reconstructed), sourceClassificationComplete: reconstructed?.coverage.sourceClassificationComplete === true,
    vulnerabilityAndSbomComplete: reviewed.vulnerability?.status === 'COMPLETE', ...semanticChecks, ...observed.report.checks };
  const phaseComplete = Object.values(checks).every((value) => value === true) && !issues.length;
  // This phase is intentionally not a signer. The next independent-policy module
  // must rerun export/Trivy/observer/providers locally before enabling PASS/FAIL votes.
  const analysis = { profile: 'restricted-oci-offline-v1', verdict: 'ABSTAIN', ready: false,
    scanPhase: phaseComplete ? 'COMPLETED_RESTRICTED_SCAN' : 'INCOMPLETE', checks, issues: [...new Set([...issues, ...pending])],
    fullBehaviorCoverage: false, limitation };
  const result = binding ? assertScanResult({ schemaVersion: '1.0.0', scanId, releaseId, artifactDigest: binding.artifactDigest,
    toolSurfaceHash: binding.toolSurfaceHash, scanStatus: findings.some(({ deterministic, severity }) => deterministic && ['HIGH', 'CRITICAL'].includes(severity)) ? 'FAILED' : 'INCONCLUSIVE',
    findings, evidenceHash: '0x' + ociHash(canonicalJson(findings)).slice(7), source: 'LIVE' }) : null;
  documents['oci/policy-review.json'] = analysis;
  documents['report.json'] = result ? { ...result, scope: 'RESTRICTED_OCI_OFFLINE_V1', scannerVersion: 'oci-security-v1' } :
    { schemaVersion: 'mcpshield.oci-incomplete-scan.v1', scanId, preparationDescriptorDigest: preparationDigest, scanStatus: 'INCONCLUSIVE', issues: analysis.issues };
  return { result, binding, analysis, bundle: createEvidenceBundle(documents) };
}

export async function prepareAndScanOciRuntime({ preparation, ...scan }) {
  const imported = await importOciRuntime(preparation);
  if (imported.phase !== 'IMPORTED') return { result: null, binding: null, bundle: null,
    analysis: { profile: 'restricted-oci-offline-v1', verdict: 'ABSTAIN', ready: false, checks: {}, issues: imported.issues, phase: imported.phase } };
  try {
    const output = await scanOciRuntime({ ...scan, descriptor: imported.descriptor, expectedDescriptorDigest: imported.descriptorDigest });
    return { ...output, runtimeTag: imported.runtimeTag, cleanup: imported.cleanup };
  } catch (error) { await imported.cleanup(); throw error; }
}
