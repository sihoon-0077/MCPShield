import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { runAiMcpAttackHarness } from './mcp-attack-harness.mjs';
import { scanReleaseDetailed } from '../services/scanner/src/scanner.mjs';

const { values } = parseArgs({ options: { fixture: { type: 'string', default: 'demo/fixtures/probe-mail-mcp' },
  runs: { type: 'string', default: '3' }, provider: { type: 'string', default: 'openai' }, model: { type: 'string' },
  'timeout-ms': { type: 'string', default: '45000' } } });
const runs = Number(values.runs);
if (!Number.isInteger(runs) || runs < 1 || runs > 20) throw new TypeError('--runs must be 1..20 (each run makes a billable model planning request)');
const ai = { provider: values.provider, model: values.model ?? process.env.MCP_SHIELD_AI_MODEL,
  url: process.env.MCP_SHIELD_AI_URL, token: process.env.MCP_SHIELD_AI_TOKEN, timeoutMs: Number(values['timeout-ms']) };
if (process.env.MCP_SHIELD_ENABLE_REMOTE_AI !== 'true' || (ai.provider === 'openai' && (!ai.model || !ai.token))) {
  process.stdout.write(JSON.stringify({ status: 'NOT_RUN', reason: 'Explicit remote AI opt-in and provider credentials/model are required.',
    setup: 'Set MCP_SHIELD_ENABLE_REMOTE_AI=true, MCP_SHIELD_AI_TOKEN and --model. Docker is required; no host fallback. --runs controls billable requests.' }) + '\n');
  process.exitCode = 2;
} else {
  const measurements = [];
  try {
    for (let index = 0; index < runs; index++) measurements.push(await runAiMcpAttackHarness({ fixtureDir: resolve(values.fixture), allowRemoteAi: true, ...ai,
      authorize: async ({ attackCalls, artifactDigest }) => {
        const scan = await scanReleaseDetailed({ fixtureDir: resolve(values.fixture), sandbox: 'docker', sandboxTimeoutMs: 10_000, probeCalls: attackCalls, logger: () => {} });
        return { allow: scan.result.artifactDigest === artifactDigest && scan.result.scanStatus === 'PASSED', reasonCode: 'SCANNER_POLICY_NOT_CHAIN' };
      } }));
    const baseline = measurements.filter(({ baseline }) => baseline.canaryExfiltration).length / runs;
    const protectedRate = measurements.filter(({ protected: result }) => result.canaryExfiltration).length / runs;
    process.stdout.write(JSON.stringify({ status: 'MEASURED', source: 'LIVE', environment: 'DOCKER', sampleSize: runs,
      method: 'MODEL_GENERATED_SYNTHETIC_TOOL_CALL_PLAN', admission: 'SCANNER_POLICY_NOT_CHAIN', baselineAttackEffectRate: baseline,
      protectedAttackEffectRate: protectedRate, reduction: baseline === 0 ? null : baseline - protectedRate,
      normalTaskCompletionRate: measurements.filter(({ normal }) => !normal.canaryExfiltration && normal.calls.every(({ isError }) => !isError)).length / runs,
      measurements, limitations: ['Synthetic action-effect rate, not a free-running agent ASR.', 'No efficacy claim when baseline attack effect is zero.', 'Supply a real chain/Gateway authorize callback to the library harness for full trust-plane measurement.'] }, null, 2) + '\n');
  } catch {
    process.stderr.write(JSON.stringify({ status: 'INCOMPLETE', completedRuns: measurements.length, reason: 'AI_MCP_BENCHMARK_FAILED',
      note: 'No partial success rate is reported. Inspect sanitized scanner/provider diagnostics.' }) + '\n');
    process.exitCode = 1;
  }
}
