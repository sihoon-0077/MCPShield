import { createHash } from 'node:crypto';
import { canonicalJson, verifyEvidenceBundle } from './evidence.mjs';
import { validatePreparedReleaseBinding } from './prepared-binding.mjs';
import { hashPreparedRuntimeDescriptor } from '../../resolver/src/runtime-descriptor.mjs';
import { closureManifest } from '../../resolver/src/closure-files.mjs';
import { toolSurfaceHash } from './tool-surface.mjs';
import { inspectPreparedSources, preparedSemanticPrompt, LOCAL_CONTRACT_DISCLOSURE } from './prepared-review.mjs';
import { citationCatalogue, promptSources, validateSemanticReport } from './semantic.mjs';
import { assertScanResult } from './schema.mjs';
import { redactEvidenceDocument, redactPromptText } from './redaction.mjs';
import { SCOPED_NODE_PROFILE, SCOPED_REVIEW_SCHEMA, SCOPED_DISCLOSURE_POLICY, checkedScopedProvenance } from './scoped-policy.mjs';
import { verifyScopedSemanticInputV2, scopedSemanticPrompt, validateScopedProbeV2 } from './scoped-semantic.mjs';
import { probeArgumentsDigest } from './mcp-probe.cjs';

const sha = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const equal = (a, b) => canonicalJson(a) === canonicalJson(b);
export const PREPARED_POLICY_CHECKS = Object.freeze(['closureIntegrityVerified', 'staticComplete', 'sbomComplete',
  'semanticComplete', 'independentCriticComplete', 'semanticNoUnresolvedRisk', 'imagePinned', 'discoveryComplete',
  'toolSurfaceStable', 'normalProbeComplete', 'adversarialProbeComplete', 'normalToolCallsSucceeded', 'adversarialToolCallsSucceeded']);

// Recompute checks from Merkle-bound objects. Never accept the scanner's advertised
// checks/PASS without evidence, or use binding-supplied hashes as trust anchors.
export function assessPreparedPolicy(bundle, result, binding, trusted) {
  return assessPolicy(bundle, result, binding, trusted, false);
}

export function assessScopedPreparedPolicy(bundle, result, binding, trusted) {
  return assessPolicy(bundle, result, binding, trusted, true);
}

function assessPolicy(bundle, result, binding, trusted, scoped) {
  const profile = scoped ? SCOPED_NODE_PROFILE : 'restricted-node-docker-v1';
  const checks = Object.fromEntries(PREPARED_POLICY_CHECKS.map((name) => [name, false]));
  const abstain = (code) => ({ profile, verdict: 'ABSTAIN', checks, issues: [code] });
  try {
    assertScanResult(result);
    if (!verifyEvidenceBundle(bundle, bundle.manifest.root) || !validatePreparedReleaseBinding(binding) ||
      binding.executionPolicy.profile !== (scoped ? SCOPED_NODE_PROFILE : 'prepared-node-observation-v1')) return abstain('PREPARED_EVIDENCE_OR_BINDING_INVALID');
    if (scoped) checkedScopedProvenance(trusted?.sourceProvenance, binding.sourceArtifactDigest);
    if (!trusted || trusted.builderImageDigest !== binding.descriptor.builderImageDigest ||
      trusted.collectorDigest !== binding.executionPolicy.collectorDigest || trusted.observerDigest !== binding.executionPolicy.observerDigest ||
      trusted.finalImageDigest !== binding.finalImageDigest || !equal(trusted.platform, binding.platform) ||
      trusted.entrypointDigest !== binding.descriptor.entrypoint.digest || !/^sha256:[a-f0-9]{64}$/.test(trusted.closureDigest) ||
      trusted.sourceDescriptorDigest !== hashPreparedRuntimeDescriptor({ ...binding.descriptor, stage: 'PREFLIGHT', finalImageDigest: null, toolSurfaceHash: null })) return abstain('PREPARED_TRUST_ANCHOR_MISMATCH');
    const read = (path) => JSON.parse(bundle.files[path]);
    const report = read('report.json');
    const observation = read('prepared/observation.json');
    if (!equal(read('prepared/binding.json'), binding) || !equal(read('runtime/descriptor.json'), binding.descriptor) ||
      !equal(read('runtime/execution-policy.json'), binding.executionPolicy) || result.artifactDigest !== binding.artifactDigest ||
      result.toolSurfaceHash !== binding.toolSurfaceHash || report.scope !== (scoped ? 'RESTRICTED_NODE_DOCKER_V2' : 'RESTRICTED_NODE_DOCKER_V1') ||
      Object.keys(result).some((field) => !equal(result[field], report[field])) || result.source !== 'LIVE' ||
      toolSurfaceHash(read('runtime/tools.json')) !== binding.toolSurfaceHash) return abstain('PREPARED_REPORT_IDENTITY_MISMATCH');
    if (observation.source !== 'LIVE_DOCKER' || observation.identity.observedDescriptorDigest !== binding.descriptorDigest ||
      observation.identity.sourceArtifactDigest !== binding.sourceArtifactDigest ||
      observation.identity.executionPolicyDigest !== binding.executionPolicyDigest ||
      observation.identity.finalImageDigest !== binding.finalImageDigest ||
      observation.identity.preparationDescriptorDigest !== hashPreparedRuntimeDescriptor({ ...binding.descriptor, toolSurfaceHash: null })) return abstain('PREPARED_OBSERVATION_IDENTITY_MISMATCH');
    const steps = observation.steps;
    const runtime = { imageDigest: binding.finalImageDigest, platform: binding.platform, argv: binding.descriptor.argv };
    const complete = (step) => step && step.protocolComplete === true && !step.timedOut && step.exitCode === 0 && !step.failureCode &&
      Number.isSafeInteger(step.pages) && step.pages >= 1 && step.pages <= 32 &&
      step.permissionProfile === 'NODE_PERMISSION_READ_ONLY_V1' && equal(step.runtimeIdentity, runtime) &&
      !step.egressEvents.some(({ type }) => type === 'EGRESS_BODY_LIMIT');
    checks.imagePinned = Object.keys(steps).length > 0 && Object.values(steps).every((step) => equal(step.runtimeIdentity, runtime));
    checks.discoveryComplete = Boolean(complete(steps.discovery));
    checks.toolSurfaceStable = checks.discoveryComplete && Object.values(steps).every((step) => step.toolSurfaceHash === binding.toolSurfaceHash);
    for (const [stage, kind] of [['normal', 'NORMAL'], ['adversarial', 'ADVERSARIAL']]) {
      const planned = observation.scenarios.filter((scenario) => scenario.kind === kind).map(({ toolCall }) => toolCall.name);
      const calls = steps[stage]?.callResults;
      checks[`${stage}ProbeComplete`] = Boolean(planned.length && complete(steps[stage]) && Array.isArray(calls) && calls.length === planned.length &&
        calls.every((call, index) => call.name === planned[index] && typeof call.isError === 'boolean' && /^[a-f0-9]{64}$/.test(call.contentHash)));
      checks[`${stage}ToolCallsSucceeded`] = checks[`${stage}ProbeComplete`] && calls.every(({ isError }) => !isError);
    }
    const deterministic = result.findings.filter(({ deterministic, stage, severity }) => deterministic && stage === 'SANDBOX' && ['HIGH', 'CRITICAL'].includes(severity));
    const effectMatches = (finding) => Object.values(steps).some((step) =>
      finding.code === 'CANARY_EXFILTRATION' ? step.canaryExfiltration === true && /^[a-f0-9]{64}$/.test(step.canaryHash) && step.canaryHash === finding.evidence.canaryHash :
      finding.code === 'UNDECLARED_EGRESS' ? step.egressEvents.some(({ type }) => type === 'EGRESS_BLOCKED') :
      finding.code === 'TOOL_SURFACE_CHANGED' && step.toolSurfaceHash && step.toolSurfaceHash !== binding.toolSurfaceHash);
    if (checks.imagePinned && deterministic.length && deterministic.every(effectMatches) && result.scanStatus === 'FAILED') {
      return { profile, verdict: 'FAIL', checks, issues: [] };
    }
    const inventory = read('static/closure-inventory.json');
    const closure = read('static/closure-report.json');
    const raw = read('static/closure-source.json');
    if (raw.complete !== true || !Array.isArray(raw.files) || raw.files.length > 8192) return abstain('PREPARED_RAW_SOURCE_EVIDENCE_REQUIRED');
    let rawBytes = 0;
    const contents = raw.files.map(({ path, base64 }) => {
      if (typeof base64 !== 'string') throw Error();
      const bytes = Buffer.from(base64, 'base64');
      rawBytes += bytes.length;
      if (bytes.toString('base64') !== base64 || rawBytes > 8 * 1024 * 1024) throw Error();
      return { path, bytes };
    });
    const independentlyReviewed = inspectPreparedSources({ ...inventory, contents });
    checks.closureIntegrityVerified = inventory.source === 'LIVE_DOCKER_IMAGE_EXPORT' && closureManifest(inventory.entries).digest === inventory.digest &&
      inventory.digest === closure.digest && inventory.digest === trusted.closureDigest && equal(inventory.entries, closure.entries) && inventory.bytes === closure.bytes &&
      inventory.entries.length <= 8192 && inventory.bytes <= 100 * 1024 * 1024 &&
      closure.sourceDescriptorDigest === hashPreparedRuntimeDescriptor({ ...binding.descriptor,
        stage: 'PREFLIGHT', finalImageDigest: null, toolSurfaceHash: null }) && closure.installScripts === false && closure.installNetwork === 'NONE';
    checks.staticComplete = checks.closureIntegrityVerified && inventory.staticComplete === true && independentlyReviewed.inventory.staticComplete &&
      equal(read('static/findings.json'), independentlyReviewed.findings) && equal(result.findings.filter(({ stage }) => stage === 'STATIC'), independentlyReviewed.findings) &&
      inventory.entries.filter(({ type }) => type === 'File').length === inventory.textFiles && inventory.textFiles === inventory.fileCount;
    const sbom = read('static/sbom.json');
    const packages = inventory.entries.filter(({ path, type }) => type === 'File' && /^(?:node_modules\/(?:@[^/]+\/)?[^/]+\/)*package.json$/.test(path));
    checks.sbomComplete = equal(sbom, independentlyReviewed.sbom) && sbom.complete === true && packages.length > 0 && packages.length === sbom.components.length &&
      packages.every(({ path, digest }) => sbom.components.some((component) => component.properties?.some((p) => p.name === 'mcpshield:installed-path' && p.value === path) &&
        component.properties?.some((p) => p.name === 'mcpshield:package-json-digest' && p.value === digest)));
    const semantic = read('semantic/reviews.json');
    if (scoped) {
      if (semantic.schemaVersion !== SCOPED_REVIEW_SCHEMA || semantic.approvalVerdict !== 'ABSTAIN' ||
        semantic.fullSourceCoverage !== false || semantic.fullBehaviorCoverage !== false ||
        semantic.evidenceMode !== binding.executionPolicy.semantic.evidenceMode || semantic.issues.length ||
        !verifyScopedSemanticInputV2({ input: semantic.input, proof: semantic.proof,
          files: independentlyReviewed.files, tools: read('runtime/tools.json'), executionPolicy: binding.executionPolicy,
          sourceProvenance: trusted.sourceProvenance, sourceArtifactDigest: binding.sourceArtifactDigest,
          runtime: { profile, runtimeDigest: binding.finalImageDigest, environmentDigest: inventory.digest } }) ||
        !semantic.proof.scopeComplete) return abstain('SCOPED_SEMANTIC_INPUT_OR_AUTHORITY_INVALID');
      const roles = semantic.input.requiredRoles;
      if (!equal(Object.keys(semantic.reviews).sort(), [...roles].sort())) return abstain('SCOPED_REQUIRED_ROLE_INCOMPLETE');
      let clean = true;
      for (const role of roles) {
        const item = semantic.reviews[role], execution = item.execution, prompt = scopedSemanticPrompt(semantic.input, role);
        if (execution.promptHash !== sha(prompt) || execution.inputDigest !== semantic.proof.inputDigest || execution.tools !== 'NONE' ||
          execution.schemaName !== `mcpshield_scoped_v2_${role}` || execution.purpose !== 'security' ||
          !['openai', 'custom'].includes(execution.provider) || execution.disclosurePolicy !== SCOPED_DISCLOSURE_POLICY ||
          execution.evidenceMode !== binding.executionPolicy.semantic.evidenceMode ||
          execution.provider === 'openai' && (execution.store !== false || !execution.model || execution.model !== execution.configuredModel)) {
          return abstain('SCOPED_SEMANTIC_ROLE_PROVENANCE_INVALID');
        }
        if (role === 'probe') {
          const plan = validateScopedProbeV2(item.report, read('runtime/tools.json'), semantic.input);
          if (!equal(observation.scenarios, plan.scenarios) || !equal(observation.generation, { ...execution, status: 'SCOPED_GENERATED_VALIDATED' })) {
            return abstain('SCOPED_PROBE_PLAN_MISMATCH');
          }
          for (const [stage, kind] of [['normal', 'NORMAL'], ['adversarial', 'ADVERSARIAL']]) {
            const calls = plan.scenarios.filter((scenario) => scenario.kind === kind).map(({ toolCall }) => toolCall);
            if (steps[stage]?.callResults?.length !== calls.length || !calls.every((call, index) =>
              steps[stage].callResults[index].name === call.name && steps[stage].callResults[index].argumentsDigest === probeArgumentsDigest(call.arguments))) {
              return abstain('SCOPED_EXECUTED_CALL_MISMATCH');
            }
          }
        } else {
          const parsed = validateSemanticReport(item.report, promptSources(prompt), citationCatalogue(semantic.input));
          if (parsed.needsHumanReview || parsed.riskClaims.length || Object.values(parsed.semanticDiff).some(Boolean)) clean = false;
        }
      }
      if (semantic.input.tier === 3) {
        const primary = semantic.reviews.analyzer.execution, second = semantic.reviews.analyzer2.execution;
        if (primary.provider !== 'openai' || second.provider !== 'openai' || !primary.configuredModel || !second.configuredModel ||
          primary.configuredModel === second.configuredModel || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(primary.responseModel ?? '') ||
          !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(second.responseModel ?? '') || primary.responseModel === second.responseModel) {
          return abstain('SCOPED_DISTINCT_SECOND_MODEL_REQUIRED');
        }
      }
      checks.semanticComplete = semantic.scopeComplete === true;
      checks.independentCriticComplete = checks.semanticComplete;
      checks.semanticNoUnresolvedRisk = clean && semantic.noUnresolvedRisk === true && !result.findings.length;
      const approved = PREPARED_POLICY_CHECKS.every((name) => checks[name]) && result.scanStatus === 'PASSED' && observation.issues.length === 0;
      return { profile, verdict: approved ? 'PASS' : 'ABSTAIN', checks, issues: approved ? [] : ['SCOPED_REVIEW_OR_OBSERVATION_INCOMPLETE'] };
    }
    if (!equal(semantic.disclosure, LOCAL_CONTRACT_DISCLOSURE)) return abstain('PREPARED_SEMANTIC_DISCLOSURE_INVALID');
    const coverage = new Map();
    let analyzerComplete = true, criticComplete = true, clean = true;
    if (!Array.isArray(semantic.reviews) || !semantic.reviews.length || semantic.reviews.length !== semantic.expectedBatches ||
      !Array.isArray(semantic.sources) || semantic.sources.length !== inventory.fileCount + 1) return abstain('PREPARED_SEMANTIC_COVERAGE_INCOMPLETE');
    for (const [index, review] of semantic.reviews.entries()) {
      if (review.batchIndex !== index || sha(canonicalJson(review.input)) !== review.inputDigest) return abstain('PREPARED_SEMANTIC_INPUT_MISMATCH');
      for (const part of review.input.excerpts) {
        const existing = coverage.get(part.path) ?? '';
        if (part.offset !== existing.length) return abstain('PREPARED_SEMANTIC_INPUT_MISMATCH');
        coverage.set(part.path, existing + part.content);
      }
      for (const role of ['analyzer', 'critic']) {
        const item = review[role];
        if (!item) { if (role === 'analyzer') analyzerComplete = false; else criticComplete = false; continue; }
        const prompt = preparedSemanticPrompt(review.input, role);
        if (item.execution.promptHash !== sha(prompt) || item.execution.tools !== 'NONE' || item.execution.schemaName !== `mcpshield_prepared_${role}` ||
          item.execution.provider !== 'custom' || !equal(item.execution.disclosure, LOCAL_CONTRACT_DISCLOSURE)) return abstain('PREPARED_SEMANTIC_PROVENANCE_MISMATCH');
        const parsed = validateSemanticReport(item.report, promptSources(prompt), citationCatalogue(review.input));
        if (parsed.needsHumanReview || parsed.riskClaims.length || Object.values(parsed.semanticDiff).some(Boolean)) clean = false;
      }
    }
    const sourceCoverage = semantic.sources.length === coverage.size && semantic.sources.every((source) =>
      coverage.get(source.path)?.length === source.length && sha(coverage.get(source.path)) === source.digest &&
      (source.path === 'MCP_TOOLS_COMPLETE.json'
        ? coverage.get(source.path) === redactPromptText(canonicalJson(redactEvidenceDocument(read('runtime/tools.json'))))
        : independentlyReviewed.files.some(({ path, rawDigest, content }) => path === source.path && rawDigest === source.rawDigest &&
          coverage.get(source.path) === redactPromptText(content))));
    checks.semanticComplete = sourceCoverage && analyzerComplete;
    checks.independentCriticComplete = sourceCoverage && criticComplete;
    checks.semanticNoUnresolvedRisk = clean && checks.semanticComplete && checks.independentCriticComplete && !result.findings.length;
    const approved = PREPARED_POLICY_CHECKS.every((name) => checks[name]) && result.scanStatus === 'PASSED' && observation.issues.length === 0;
    return { profile, verdict: approved ? 'PASS' : 'ABSTAIN', checks,
      issues: approved ? [] : ['PREPARED_REVIEW_OR_OBSERVATION_INCOMPLETE'] };
  } catch { return abstain('PREPARED_EVIDENCE_INCOMPLETE_OR_INVALID'); }
}
