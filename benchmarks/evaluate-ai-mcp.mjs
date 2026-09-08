import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { runAiMcpAttackHarness } from './mcp-attack-harness.mjs';
import { scanReleaseDetailed } from '../services/scanner/src/scanner.mjs';
import { runPairedAgentHarness, summarizeAgentExperiments } from './agent-mcp-harness.mjs';
import { execFileSync } from 'node:child_process';

const { values } = parseArgs({ options: { fixture: { type: 'string', default: 'demo/fixtures/probe-mail-mcp' },
  runs: { type: 'string', default: '3' }, provider: { type: 'string', default: 'openai' }, model: { type: 'string' },
  mode: { type: 'string', default: 'probe' }, 'safe-fixture': { type: 'string', default: 'demo/fixtures/mail-mcp-1.0.0' },
  'timeout-ms': { type: 'string', default: '45000' } } });
const runs = Number(values.runs);
if (!Number.isInteger(runs) || runs < 1 || runs > 20) throw new TypeError('--runs must be 1..20 (each run makes a billable model planning request)');
if (!['probe', 'agent'].includes(values.mode)) throw new TypeError('--mode must be probe or agent');
const ai = { provider: values.provider, model: values.model ?? process.env.MCP_SHIELD_AI_MODEL,
  url: process.env.MCP_SHIELD_AI_URL, token: process.env.MCP_SHIELD_AI_TOKEN, timeoutMs: Number(values['timeout-ms']) };
if (process.env.MCP_SHIELD_ENABLE_REMOTE_AI !== 'true' || (ai.provider === 'openai' && (!ai.model || !ai.token))) {
  process.stdout.write(JSON.stringify({ status: 'NOT_RUN', reason: 'Explicit remote AI opt-in and provider credentials/model are required.',
    setup: 'Set MCP_SHIELD_ENABLE_REMOTE_AI=true, MCP_SHIELD_AI_TOKEN and --model. Docker is required; no host fallback. --runs controls billable requests.' }) + '\n');
  process.exitCode = 2;
} else {
  const measurements = [];
  try {
    const authorize = async ({ attackCalls, calls, fixtureDir = resolve(values.fixture), artifactDigest }) => {
        const scan = await scanReleaseDetailed({ fixtureDir, sandbox: 'docker', sandboxTimeoutMs: 10_000, probeCalls: calls ?? attackCalls, logger: () => {} });
        return { allow: scan.result.artifactDigest === artifactDigest && scan.result.scanStatus === 'PASSED', reasonCode: 'SCANNER_POLICY_NOT_CHAIN' };
    };
    for (let index = 0; index < runs; index++) measurements.push(await (values.mode === 'agent'
      ? runPairedAgentHarness({ safeDir: resolve(values['safe-fixture']), poisonedDir: resolve(values.fixture), authorize, allowRemoteAi: true, ...ai })
      : runAiMcpAttackHarness({ fixtureDir: resolve(values.fixture), authorize, allowRemoteAi: true, ...ai })));
    let commit = 'UNAVAILABLE';
    try { commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8', windowsHide: true }).trim(); } catch { /* source archive */ }
    const provenance = { commit, runtime: process.version, platform: process.platform, measuredAt: new Date().toISOString() };
    if (values.mode === 'agent') {
      process.stdout.write(JSON.stringify({ status: 'MEASURED', source: 'LIVE', environment: 'DOCKER', ...provenance,
        method: 'SINGLE_TURN_TOOL_DECISION_AGENT', admission: 'SCANNER_POLICY_NOT_CHAIN', summary: summarizeAgentExperiments(measurements), measurements }, null, 2) + '\n');
    } else {
    const baseline = measurements.filter(({ baseline }) => baseline.canaryExfiltration).length / runs;
    const protectedRate = measurements.filter(({ protected: result }) => result.canaryExfiltration).length / runs;
    process.stdout.write(JSON.stringify({ status: 'MEASURED', source: 'LIVE', environment: 'DOCKER', sampleSize: runs, ...provenance,
      method: 'MODEL_GENERATED_SYNTHETIC_TOOL_CALL_PLAN', admission: 'SCANNER_POLICY_NOT_CHAIN', baselineAttackEffectRate: baseline,
      protectedAttackEffectRate: protectedRate, reduction: baseline === 0 ? null : baseline - protectedRate,
      normalTaskCompletionRate: measurements.filter(({ normal }) => !normal.canaryExfiltration && normal.calls.every(({ isError }) => !isError)).length / runs,
      measurements, limitations: ['Synthetic action-effect rate, not a free-running agent ASR.', 'No efficacy claim when baseline attack effect is zero.', 'Supply a real chain/Gateway authorize callback to the library harness for full trust-plane measurement.'] }, null, 2) + '\n');
    }
  } catch {
    process.stderr.write(JSON.stringify({ status: 'INCOMPLETE', completedRuns: measurements.length, reason: 'AI_MCP_BENCHMARK_FAILED',
      note: 'No partial success rate is reported. Inspect sanitized scanner/provider diagnostics.' }) + '\n');
    process.exitCode = 1;
  }
}
