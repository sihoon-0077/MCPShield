import { runSandbox } from '../services/scanner/src/sandbox.mjs';
import { generateSyntheticProbes } from '../services/scanner/src/probes.mjs';
import { artifactDigest, loadManifest, toolSurfaceHash } from '../services/scanner/src/scanner.mjs';

// Actual MCP calls and sink effects in Docker; caller supplies the real admission integration.
// The supplied calls are a reproducible scripted attack, not a claim about any LLM's ASR.
export async function runMcpAttackHarness({ fixtureDir, entrypoint = 'index.mjs', authorize, normalCalls = [{ name: 'list_messages', arguments: {} }], attackCalls = [{ name: 'export_context', arguments: {} }] }) {
  if (typeof authorize !== 'function') throw new TypeError('a real admission callback is required');
  const options = { mode: 'docker', fixtureDir, entrypoint, timeoutMs: 10_000, mcpProbe: true };
  const normal = await runSandbox({ ...options, probeCalls: normalCalls });
  const unprotected = await runSandbox({ ...options, probeCalls: attackCalls });
  if (!normal.mcpReport?.complete || normal.error || !unprotected.mcpReport?.complete || unprotected.error) throw new Error('MCP harness execution incomplete');
  const decision = await authorize();
  if (!decision || typeof decision.allow !== 'boolean' || typeof decision.reasonCode !== 'string') throw new TypeError('admission callback must return allow/reasonCode');
  const protectedRun = decision.allow ? await runSandbox({ ...options, probeCalls: attackCalls }) : null;
  if (protectedRun && (!protectedRun.mcpReport?.complete || protectedRun.error)) throw new Error('protected MCP harness execution incomplete');
  return { status: 'measured', source: 'LIVE', environment: 'DOCKER', model: 'NONE_SCRIPTED_CALLS', sampleSize: 1,
    normal: { completed: true, canaryExfiltration: normal.canaryObserved, calls: normal.mcpReport.callResults },
    baseline: { spawned: true, canaryExfiltration: unprotected.canaryObserved, calls: unprotected.mcpReport.callResults },
    protected: { spawned: decision.allow, reasonCode: decision.reasonCode, canaryExfiltration: protectedRun?.canaryObserved ?? false, calls: protectedRun?.mcpReport?.callResults ?? [] },
    baselineAttackSuccessRate: Number(unprotected.canaryObserved), protectedAttackSuccessRate: Number(protectedRun?.canaryObserved ?? false),
    limitations: ['Scripted malicious MCP calls, not general LLM attack success.', 'Single synthetic artifact and one run; report aggregate multi-run experiments separately.'] };
}

// One bounded model-generated tool-call plan, followed by actual isolated MCP calls.
// This is an action-effect benchmark, not a free-running conversational agent benchmark.
export async function runAiMcpAttackHarness({ fixtureDir, authorize, allowRemoteAi = false, ...aiOptions }) {
  if (!allowRemoteAi) throw new TypeError('AI harness requires explicit remote AI opt-in');
  if (typeof authorize !== 'function') throw new TypeError('a real admission callback is required');
  const manifest = await loadManifest(fixtureDir);
  const digest = await artifactDigest(fixtureDir);
  const discovery = await runSandbox({ mode: 'docker', fixtureDir, entrypoint: manifest.entrypoint, timeoutMs: 10_000, mcpProbe: true });
  if (!discovery.mcpReport?.complete || discovery.error || toolSurfaceHash(discovery.mcpReport.tools) !== toolSurfaceHash(manifest.tools)) throw new Error('AI harness observed an incomplete or changed MCP surface');
  const generated = await generateSyntheticProbes({ ...aiOptions, tools: discovery.mcpReport.tools });
  if (await artifactDigest(fixtureDir) !== digest) throw new Error('AI harness artifact changed during planning');
  const normalCalls = generated.scenarios.filter(({ kind }) => kind === 'NORMAL').map(({ toolCall }) => toolCall);
  const attackCalls = generated.scenarios.filter(({ kind }) => kind === 'ADVERSARIAL').map(({ toolCall }) => toolCall);
  const measured = await runMcpAttackHarness({ fixtureDir, entrypoint: manifest.entrypoint,
    authorize: () => authorize({ artifactDigest: digest, toolSurfaceHash: toolSurfaceHash(manifest.tools), normalCalls, attackCalls }), normalCalls, attackCalls });
  if (await artifactDigest(fixtureDir) !== digest) throw new Error('AI harness artifact changed during execution');
  return { ...measured, model: generated.execution.responseModel ?? generated.execution.model,
    artifactDigest: digest, toolSurfaceHash: toolSurfaceHash(manifest.tools), planning: generated.execution,
    method: 'MODEL_GENERATED_SYNTHETIC_TOOL_CALL_PLAN', attackEfficacy: measured.baseline.canaryExfiltration ? 'BASELINE_EFFECT_OBSERVED' : 'NO_BASELINE_EFFECT',
    limitations: ['One model-generated plan, not a free-running multi-turn agent or general LLM ASR.', 'One synthetic artifact; repeat across independently labeled corpora and models.', 'Admission callback identity determines whether protection is scanner-only or a real validator/chain/Gateway integration.'] };
}
