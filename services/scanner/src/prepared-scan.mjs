import { createHash, randomUUID } from 'node:crypto';
import { prepareNpmClosure, readPreparedClosure } from '../../resolver/src/npm-closure.mjs';
import { generateNpmLock } from '../../resolver/src/generated-lock.mjs';
import { hashPreparedRuntimeDescriptor } from '../../resolver/src/runtime-descriptor.mjs';
import { canonicalJson, createEvidenceBundle } from './evidence.mjs';
import { observePreparedRuntime } from './prepared-runtime.mjs';
import { createPreparedReleaseBinding } from './prepared-binding.mjs';
import { inspectPreparedSources, reviewPreparedSemantics } from './prepared-review.mjs';
import { assessPreparedPolicy } from './prepared-policy.mjs';
import { readTrustedPreparedIdentity } from './prepared-trust.mjs';
import { assertScanResult } from './schema.mjs';
import { redactEvidenceDocument } from './redaction.mjs';

export { assessPreparedPolicy } from './prepared-policy.mjs';
export { readTrustedPreparedIdentity } from './prepared-trust.mjs';
const hash = (value) => `0x${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
const LIMITATION = 'Approval applies only to restricted-node-docker-v1 observations and the stricter network-none Gateway profile. Docker is the isolation boundary; Node permissions/hooks are defense in depth, not a proof of all behavior.';

// Independent validator-local verification, not a scanner-supplied trust object.
// The unstarted Docker export reads bytes only; no candidate executable is launched.
export async function readTrustedPreparedRuntime({ descriptor, expectedDescriptorDigest, builderImageDigest }) {
  const trusted = readTrustedPreparedIdentity(builderImageDigest);
  if (descriptor.builderImageDigest !== builderImageDigest) throw Error('PREPARED_TRUST_ANCHOR_MISMATCH');
  const closure = await readPreparedClosure({ descriptor, expectedDescriptorDigest });
  return { ...trusted, finalImageDigest: descriptor.finalImageDigest, platform: descriptor.platform,
    closureDigest: closure.digest, sourceDescriptorDigest: closure.report.sourceDescriptorDigest,
    entrypointDigest: closure.entries.find(({ path }) => path === descriptor.entrypoint.path)?.digest };
}

export async function scanPreparedRuntime({ descriptor, expectedDescriptorDigest, sourceReleaseId, releaseId,
  scanId = randomUUID(), ai, probePlan, timeoutMs = 15_000, trusted }) {
  if (hashPreparedRuntimeDescriptor(descriptor) !== expectedDescriptorDigest || descriptor.stage !== 'CLOSURE_PREPARED' ||
    descriptor.profile !== 'npm-closure-v1' || !/^0x[a-f0-9]{64}$/.test(sourceReleaseId) ||
    !/^.+@[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/.test(releaseId)) throw Error('PREPARED_SCAN_INPUT_INVALID');
  let closure = null;
  let review = null;
  const issues = [];
  try {
    closure = await readPreparedClosure({ descriptor, expectedDescriptorDigest });
    review = inspectPreparedSources(closure);
    issues.push(...review.issues);
  } catch { issues.push('PREPARED_CLOSURE_REVIEW_INCOMPLETE'); }
  const preparation = { ...descriptor, toolSurfaceHash: null };
  const observed = await observePreparedRuntime({ descriptor: preparation, expectedDescriptorDigest: hashPreparedRuntimeDescriptor(preparation),
    probePlan, ai: probePlan ? undefined : ai, timeoutMs });
  const documents = Object.fromEntries(Object.entries(observed.bundle.files).filter(([path]) => path !== 'report.json').map(([path, content]) => [path, JSON.parse(content)]));
  const binding = observed.observedDescriptor ? createPreparedReleaseBinding({ sourceReleaseId, descriptor: observed.observedDescriptor,
    executionPolicy: documents['runtime/execution-policy.json'] }) : null;
  if (!binding) return { result: null, binding: null, bundle: observed.bundle,
    analysis: { profile: 'restricted-node-docker-v1', verdict: 'ABSTAIN', checks: {}, issues: [...issues, 'PREPARED_DISCOVERY_REQUIRED'] } };
  // Rescans must preserve the registered observed identity, not silently create a new release.
  if (descriptor.toolSurfaceHash !== null && binding.descriptorDigest !== expectedDescriptorDigest) issues.push('PREPARED_REGISTERED_SURFACE_CHANGED');
  const semantic = review ? await reviewPreparedSemantics({ files: review.files, tools: documents['runtime/tools.json'], releaseId, ai }) :
    { reviews: [], complete: false, independentCriticComplete: false, noUnresolvedRisk: false, findings: [], issues: ['PREPARED_CLOSURE_REVIEW_REQUIRED'] };
  issues.push(...semantic.issues, ...observed.report.issues);
  const findings = [...(review?.findings ?? []), ...semantic.findings, ...observed.report.findings.map((finding) => ({
    code: finding.code, deterministic: true, severity: finding.code === 'CANARY_EXFILTRATION' ? 'CRITICAL' : 'HIGH', stage: 'SANDBOX',
    message: 'An independent synthetic sink/proxy or full MCP surface comparison observed a restricted-profile violation.',
    evidence: finding.evidence }))];
  const deterministicFailure = findings.some(({ deterministic, severity }) => deterministic && ['HIGH', 'CRITICAL'].includes(severity));
  const optimisticComplete = !issues.length && !findings.length && review?.inventory.staticComplete && review?.sbom.complete &&
    semantic.complete && semantic.independentCriticComplete && semantic.noUnresolvedRisk &&
    ['imagePinned', 'discoveryComplete', 'toolSurfaceStable', 'normalProbeComplete', 'adversarialProbeComplete', 'normalToolCallsSucceeded', 'adversarialToolCallsSucceeded']
      .every((name) => observed.report.checks[name]);
  const result = assertScanResult({ schemaVersion: '1.0.0', scanId, releaseId, artifactDigest: binding.artifactDigest,
    toolSurfaceHash: binding.toolSurfaceHash, scanStatus: deterministicFailure ? 'FAILED' : optimisticComplete ? 'PASSED' : 'INCONCLUSIVE',
    findings: redactEvidenceDocument(findings), evidenceHash: hash(findings), source: 'LIVE' });
  Object.assign(documents, { 'prepared/observation.json': observed.report, 'prepared/binding.json': binding,
    'runtime/descriptor.json': binding.descriptor,
    'static/closure-inventory.json': review ? { ...review.inventory, source: closure.source } : { staticComplete: false },
    // Raw source is encrypted evidence only. Over-budget evidence is explicitly
    // incomplete; it can support observed FAIL, never prepared-profile PASS.
    'static/closure-source.json': closure && closure.bytes <= 8 * 1024 * 1024
      ? { complete: true, files: closure.contents.map(({ path, bytes }) => ({ path, base64: bytes.toString('base64') })) }
      : { complete: false, reason: 'PREPARED_SOURCE_EVIDENCE_BUDGET_EXCEEDED', limitBytes: 8 * 1024 * 1024 },
    'static/closure-report.json': closure?.report ?? null, 'static/sbom.json': review?.sbom ?? { complete: false },
    'static/findings.json': review?.findings ?? [], 'semantic/reviews.json': semantic });
  const updateReport = () => { documents['report.json'] = { ...result, scope: 'RESTRICTED_NODE_DOCKER_V1', scannerVersion: 'prepared-security-v1' }; };
  updateReport();
  let bundle = createEvidenceBundle(documents);
  // This scanner already exported the actual image. A validator must independently
  // obtain its own context with readTrustedPreparedRuntime, never reuse this object.
  const runtimeTrust = closure ? { ...trusted, finalImageDigest: descriptor.finalImageDigest, platform: descriptor.platform,
    closureDigest: closure.digest, sourceDescriptorDigest: closure.report.sourceDescriptorDigest,
    entrypointDigest: closure.entries.find(({ path }) => path === descriptor.entrypoint.path)?.digest } : trusted;
  let analysis = assessPreparedPolicy(bundle, result, binding, runtimeTrust);
  if (analysis.verdict === 'ABSTAIN' && result.scanStatus === 'PASSED') {
    result.scanStatus = 'INCONCLUSIVE'; updateReport(); bundle = createEvidenceBundle(documents);
    analysis = assessPreparedPolicy(bundle, result, binding, runtimeTrust);
  }
  analysis = { ...analysis, issues: [...new Set([...analysis.issues, ...issues])], fullBehaviorCoverage: false, limitation: LIMITATION };
  if (analysis.issues.length && analysis.verdict === 'PASS') analysis.verdict = 'ABSTAIN';
  documents['prepared/policy-review.json'] = analysis;
  return { result, binding, analysis, bundle: createEvidenceBundle(documents) };
}

export async function prepareAndScanRuntime({ preparation, sourceReleaseId, releaseId, scanId, ai, probePlan, timeoutMs,
  trusted = readTrustedPreparedIdentity(preparation.builderImageDigest) }, acquisitionOptions) {
  let prepared = await prepareNpmClosure(preparation, acquisitionOptions);
  let generated;
  if (prepared.phase === 'NOT_RUN' && prepared.issues.length === 1 && prepared.issues[0] === 'RUNTIME_LOCK_REQUIRED') {
    generated = await generateNpmLock(preparation, acquisitionOptions);
    if (generated.lockGenerated) prepared = await prepareNpmClosure({ ...preparation, generatedLock: generated.generatedLock }, acquisitionOptions);
    else prepared = generated;
  }
  if (prepared.phase !== 'CLOSURE_PREPARED') return { result: null, binding: null, bundle: null,
    analysis: { profile: 'restricted-node-docker-v1', verdict: 'ABSTAIN', checks: {}, issues: prepared.issues, phase: prepared.phase } };
  try {
    const scanned = await scanPreparedRuntime({ descriptor: prepared.descriptor, expectedDescriptorDigest: prepared.descriptorDigest,
      sourceReleaseId, releaseId, scanId, ai, probePlan, timeoutMs, trusted });
    if (generated?.generation && scanned.bundle) scanned.bundle = createEvidenceBundle({
      ...Object.fromEntries(Object.entries(scanned.bundle.files).map(([path, content]) => [path, JSON.parse(content)])),
      'prepared/lock-generation.json': generated.generation });
    return { ...scanned, runtimeTag: prepared.runtimeTag, cleanup: prepared.cleanup };
  } catch (error) {
    await prepared.cleanup();
    throw error;
  }
}
