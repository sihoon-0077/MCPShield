import assert from 'node:assert/strict';
import test from 'node:test';
import { assessPreparedObservation, observePreparedRuntime } from '../../services/scanner/src/prepared-runtime.mjs';
import { runSandbox } from '../../services/scanner/src/sandbox.mjs';
import { toolSurfaceHash } from '../../services/scanner/src/scanner.mjs';

const runtime = { imageDigest: `sha256:${'a'.repeat(64)}`, platform: { os: 'linux', architecture: 'amd64' },
  argv: ['/usr/local/bin/node', '/app/server.js'] };
const tools = ['list_messages', 'export_context'].map((name) => ({ name, inputSchema: { type: 'object', properties: {}, additionalProperties: false } }));
const scenarios = ['NORMAL', 'ADVERSARIAL'].map((kind, index) => ({ kind, toolCall: { name: tools[index].name, arguments: {} } }));
const result = (calls = []) => ({ runtimeIdentity: runtime, error: null, exitCode: 0, timedOut: false, observations: [], egressEvents: [],
  canaryObserved: false, mcpReport: { complete: true, permissionProfile: 'NODE_PERMISSION_READ_ONLY_V1', tools: structuredClone(tools), pages: 2,
    callResults: calls.map((name) => ({ name, isError: false, contentHash: 'c'.repeat(64) })) } });

test('prepared observation separates actual protocol/call completion from coverage and approval', () => {
  const steps = { discovery: result(), normal: result(['list_messages']), adversarial: result(['export_context']) };
  const assessment = assessPreparedObservation({ runtime, steps, scenarios });
  assert.equal(assessment.status, 'INCONCLUSIVE');
  assert.equal(assessment.ready, false);
  assert.equal(assessment.toolSurfaceHash, toolSurfaceHash(tools));
  assert.equal(assessment.observationStatus, 'COMPLETED_LIMITED_NODE_PROFILE');
  for (const field of ['imagePinned', 'discoveryComplete', 'toolSurfaceStable', 'normalProbeComplete', 'adversarialProbeComplete',
    'normalToolCallsSucceeded', 'adversarialToolCallsSucceeded']) assert.equal(assessment.checks[field], true, field);
  assert.equal(assessment.checks.fullBehaviorCoverage, false);
  assert.equal(assessment.checks.approvalReady, false);
  steps.adversarial.canaryObserved = true;
  steps.adversarial.canaryHash = 'd'.repeat(64);
  steps.adversarial.canaryType = 'CUSTOMER_RECORD';
  const failed = assessPreparedObservation({ runtime, steps, scenarios });
  assert.equal(failed.status, 'FAILED');
  assert.equal(failed.findings[0].evidence.observer, 'INDEPENDENT_SYNTHETIC_SINK');
  assert.equal(failed.findings[0].evidence.canaryHash, 'd'.repeat(64));
});

test('missing pagination/calls, image drift and error responses never satisfy completed observation', () => {
  const steps = { discovery: result(), normal: result(['list_messages']), adversarial: result(['export_context']) };
  for (const mutate of [
    (value) => { value.discovery.mcpReport.complete = false; },
    (value) => { value.normal.mcpReport.callResults = []; },
    (value) => { value.adversarial.timedOut = true; },
    (value) => { value.normal.runtimeIdentity = { ...runtime, imageDigest: `sha256:${'b'.repeat(64)}` }; },
  ]) {
    const altered = structuredClone(steps); mutate(altered);
    assert.equal(assessPreparedObservation({ runtime, steps: altered, scenarios }).observationStatus, 'INCOMPLETE');
  }
  const toolError = structuredClone(steps); toolError.normal.mcpReport.callResults[0].isError = true;
  const errored = assessPreparedObservation({ runtime, steps: toolError, scenarios });
  assert.equal(errored.checks.normalProbeComplete, true);
  assert.equal(errored.checks.normalToolCallsSucceeded, false);
  const changed = structuredClone(steps); changed.adversarial.mcpReport.tools[0].description = 'unexpected change';
  assert.ok(assessPreparedObservation({ runtime, steps: changed, scenarios }).findings.some(({ code }) => code === 'TOOL_SURFACE_CHANGED'));
  const forgedHooks = structuredClone(steps); forgedHooks.normal.observations.push({ type: 'FS_READ', target: 'INJECTED_CANARY' });
  assert.equal(assessPreparedObservation({ runtime, steps: forgedHooks, scenarios }).findings.length, 0);
});

test('prepared sandbox rejects local execution, mutable images, mixed fixture identity and path/argv substitution before Docker', async () => {
  for (const options of [
    { mode: 'local', preparedRuntime: runtime, mcpProbe: true },
    { mode: 'docker', preparedRuntime: { ...runtime, imageDigest: 'node:22-alpine' }, mcpProbe: true },
    { mode: 'docker', preparedRuntime: runtime, mcpProbe: true, fixtureDir: 'demo/fixtures/mail-mcp-1.0.0' },
    { mode: 'docker', preparedRuntime: { ...runtime, argv: ['/usr/local/bin/node', '/app/../etc/file.js'] }, mcpProbe: true },
    { mode: 'docker', preparedRuntime: { ...runtime, argv: ['/usr/local/bin/node', '/app/server.js', '--permission=false'] }, mcpProbe: true },
  ]) await assert.rejects(() => runSandbox(options), /PREPARED_SANDBOX_INPUT_INVALID/);
  await assert.rejects(() => observePreparedRuntime({ descriptor: { stage: 'READY' }, expectedDescriptorDigest: 'invented' }), /RUNTIME_DESCRIPTOR_INVALID/);
});
