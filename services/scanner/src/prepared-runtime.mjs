import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hashPreparedRuntimeDescriptor } from '../../resolver/src/runtime-preflight.mjs';
import { canonicalJson, createEvidenceBundle } from './evidence.mjs';
import { toolSurfaceHash } from './scanner.mjs';
import { runSandbox } from './sandbox.mjs';
import { validateProbePlan, generateSyntheticProbes } from './probes.mjs';
import { redactEvidenceDocument } from './redaction.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const runtimeOf = (descriptor) => ({ imageDigest: descriptor.finalImageDigest, platform: descriptor.platform, argv: descriptor.argv });

function surfaceOf(result) {
  const report = result?.mcpReport;
  if (!report?.complete || !Array.isArray(report.tools) || report.tools.length > 128 || report.tools.some((tool) =>
    !tool || typeof tool.name !== 'string' || !tool.name || tool.name.length > 128 || /[\x00-\x1f\x7f]/.test(tool.name) ||
    !tool.inputSchema || typeof tool.inputSchema !== 'object' || Array.isArray(tool.inputSchema))) return null;
  if (new Set(report.tools.map(({ name }) => name)).size !== report.tools.length) return null;
  try { return toolSurfaceHash(report.tools); } catch { return null; }
}

function protocolComplete(result, runtime) {
  return Boolean(result && !result.error && !result.timedOut && result.exitCode === 0 && surfaceOf(result) &&
    result.mcpReport.permissionProfile === 'NODE_PERMISSION_READ_ONLY_V1' &&
    canonicalJson(result.runtimeIdentity ?? null) === canonicalJson(runtime));
}

// Pure assessment for replay/contract tests. It does not assert that supplied observations are LIVE.
export function assessPreparedObservation({ runtime, steps, scenarios = [] }) {
  const initialHash = surfaceOf(steps.discovery);
  const findings = [];
  for (const [stage, result] of Object.entries(steps)) {
    if (result.canaryObserved) findings.push({ code: 'CANARY_EXFILTRATION', stage, deterministic: true,
      evidence: { canaryHash: result.canaryHash, canaryType: result.canaryType, observer: 'INDEPENDENT_SYNTHETIC_SINK' } });
    if (result.egressEvents?.some(({ type }) => type === 'EGRESS_BLOCKED')) findings.push({ code: 'UNDECLARED_EGRESS', stage,
      deterministic: true, evidence: { observer: 'INDEPENDENT_SYNTHETIC_PROXY' } });
    const observed = surfaceOf(result);
    if (initialHash && observed && initialHash !== observed) findings.push({ code: 'TOOL_SURFACE_CHANGED', stage,
      deterministic: true, evidence: { expectedToolSurfaceHash: initialHash, observedToolSurfaceHash: observed } });
  }
  const checks = { imagePinned: Object.values(steps).length > 0 && Object.values(steps).every((result) =>
    canonicalJson(result.runtimeIdentity ?? null) === canonicalJson(runtime)),
    discoveryComplete: protocolComplete(steps.discovery, runtime), toolSurfaceStable: Boolean(initialHash) &&
      Object.values(steps).every((result) => surfaceOf(result) === initialHash),
    normalProbeComplete: false, adversarialProbeComplete: false, normalToolCallsSucceeded: false,
    adversarialToolCallsSucceeded: false, fullBehaviorCoverage: false, approvalReady: false };
  for (const [stage, kind] of [['normal', 'NORMAL'], ['adversarial', 'ADVERSARIAL']]) {
    const expected = scenarios.filter((scenario) => scenario.kind === kind).map(({ toolCall }) => toolCall.name);
    const calls = steps[stage]?.mcpReport?.callResults;
    const completed = expected.length > 0 && protocolComplete(steps[stage], runtime) && Array.isArray(calls) &&
      calls.length === expected.length && calls.every((call, index) => call.name === expected[index] && typeof call.isError === 'boolean' && /^[a-f0-9]{64}$/.test(call.contentHash));
    checks[`${stage}ProbeComplete`] = completed;
    checks[`${stage}ToolCallsSucceeded`] = completed && calls.every((call) => !call.isError);
  }
  return { status: findings.length ? 'FAILED' : 'INCONCLUSIVE', ready: false, checks, findings,
    observationStatus: checks.discoveryComplete && checks.toolSurfaceStable && checks.normalProbeComplete && checks.adversarialProbeComplete
      ? 'COMPLETED_LIMITED_NODE_PROFILE' : 'INCOMPLETE',
    toolSurfaceHash: initialHash,
    coverage: { isolationBoundary: 'DOCKER', nodeHooks: 'UNTRUSTED_BEST_EFFORT', nodePermissionModel: 'DEFENSE_IN_DEPTH_NOT_MALICIOUS_CODE_BOUNDARY',
      independentEffects: 'SYNTHETIC_CANARY_SINK_AND_PROXY', fullBehaviorCoverage: false } };
}

function stepEvidence(result) {
  if (!result) return null;
  return { timedOut: Boolean(result.timedOut), exitCode: result.exitCode ?? null,
    protocolComplete: result.mcpReport?.complete === true, pages: result.mcpReport?.pages ?? null,
    protocolVersion: result.mcpReport?.protocolVersion ?? null,
    callResults: result.mcpReport?.callResults ?? [], canaryExfiltration: Boolean(result.canaryObserved),
    canaryHash: result.canaryObserved ? result.canaryHash : null, canaryType: result.canaryType ?? null,
    egressEvents: result.egressEvents ?? [], nodeHookObservations: result.observations ?? [],
    failureCode: result.error || result.mcpReport?.error ? 'PREPARED_SANDBOX_OR_PROTOCOL_INCOMPLETE' : null };
}

export async function observePreparedRuntime({ descriptor, expectedDescriptorDigest, probePlan, ai,
  timeoutMs = 15_000, egressAllowHosts = ['mail-api.local', 'exfil-sink.local'] }) {
  if (hashPreparedRuntimeDescriptor(descriptor) !== expectedDescriptorDigest || descriptor.stage !== 'CLOSURE_PREPARED' ||
    descriptor.profile !== 'npm-closure-v1' || descriptor.toolSurfaceHash !== null) throw new TypeError('PREPARED_DESCRIPTOR_IDENTITY_INVALID');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30_000) throw new TypeError('PREPARED_TIMEOUT_INVALID');
  if (probePlan && ai?.allowRemoteAi) throw new TypeError('PREPARED_PROBE_MODE_AMBIGUOUS');
  if (!Array.isArray(egressAllowHosts) || egressAllowHosts.length > 32 || egressAllowHosts.some((name) =>
    typeof name !== 'string' || !/^[a-z0-9][a-z0-9.-]*\.(?:local|test)$/.test(name))) throw new TypeError('PREPARED_EGRESS_POLICY_INVALID');
  egressAllowHosts = [...new Set(egressAllowHosts)].sort();
  const runtime = runtimeOf(descriptor);
  const scanId = randomUUID();
  const steps = {};
  let plan = { scenarios: [] };
  let issue = null;
  const executionPolicy = { profile: 'prepared-node-observation-v1', nodeArguments: ['--permission', '--allow-fs-read=/app',
    '--allow-fs-read=/observer', '--allow-fs-read=/home/test', '--require', '/observer/observer-preload.cjs'],
    collectorDigest: digest(await readFile(join(HERE, 'mcp-probe.cjs'))), observerDigest: digest(await readFile(join(HERE, 'observer-preload.cjs'))),
    egressAllowHosts, isolation: 'READ_ONLY_NON_ROOT_DOCKER_INTERNAL_NETWORK', imageDigestKind: 'DOCKER_IMAGE_CONFIG_ID' };
  const run = (probeCalls) => runSandbox({ mode: 'docker', preparedRuntime: runtime, timeoutMs, scanId: randomUUID(), mcpProbe: true, probeCalls, egressAllowHosts });
  try {
    steps.discovery = await run([]);
    if (!protocolComplete(steps.discovery, runtime)) throw Error('PREPARED_DISCOVERY_INCOMPLETE');
    const tools = steps.discovery.mcpReport.tools;
    if (probePlan) plan = validateProbePlan(probePlan, tools);
    else if (ai?.allowRemoteAi) plan = await generateSyntheticProbes({ ...ai, tools });
    else throw Error('PREPARED_NORMAL_AND_ADVERSARIAL_PROBES_REQUIRED');
    for (const [stage, kind] of [['normal', 'NORMAL'], ['adversarial', 'ADVERSARIAL']]) {
      steps[stage] = await run(plan.scenarios.filter((scenario) => scenario.kind === kind).map(({ toolCall }) => toolCall));
    }
  } catch (error) { issue = /^PREPARED_[A-Z_]+$/.test(error.message) ? error.message : 'PREPARED_OBSERVATION_FAILED_OR_PLAN_UNSAFE'; }
  const assessment = assessPreparedObservation({ runtime, steps, scenarios: plan.scenarios });
  const observedDescriptor = assessment.toolSurfaceHash ? { ...descriptor, toolSurfaceHash: assessment.toolSurfaceHash } : null;
  const report = redactEvidenceDocument({ schemaVersion: 'mcpshield.prepared-observation.v1', scanId, source: Object.keys(steps).length ? 'LIVE_DOCKER' : 'NOT_RUN',
    ...assessment, identity: { profile: 'npm-closure-v1', sourceArtifactDigest: descriptor.sourceTreeDigest,
      preparationDescriptorDigest: expectedDescriptorDigest,
      observedDescriptorDigest: observedDescriptor ? hashPreparedRuntimeDescriptor(observedDescriptor) : null,
      finalImageDigest: descriptor.finalImageDigest, imageDigestKind: 'DOCKER_IMAGE_CONFIG_ID',
      executionPolicyDigest: digest(canonicalJson(executionPolicy)) },
    issues: issue ? [issue] : [], scenarios: plan.scenarios, generation: plan.execution ?? { status: plan.scenarios.length ? 'MANUAL_VALIDATED' : 'NOT_GENERATED' },
    steps: Object.fromEntries(Object.entries(steps).map(([stage, result]) => [stage, stepEvidence(result)])),
    pending: ['FULL_BEHAVIOR_COVERAGE', 'PREPARED_PROFILE_STATIC_AI_REVIEW', 'VALIDATOR_APPROVAL', 'GATEWAY_RELEASE_IDENTITY_BINDING'] });
  const bundle = createEvidenceBundle({ 'report.json': report, 'runtime/execution-policy.json': executionPolicy,
    'runtime/descriptor.redacted.json': redactEvidenceDocument(observedDescriptor ?? descriptor),
    'runtime/tools.redacted.json': redactEvidenceDocument(steps.discovery?.mcpReport?.tools ?? []) });
  return { report, observedDescriptor, bundle };
}
