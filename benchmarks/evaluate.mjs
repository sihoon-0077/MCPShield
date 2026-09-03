import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRelease } from '../services/scanner/src/scanner.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const safe = join(ROOT, 'demo/fixtures/mail-mcp-1.0.0');
const malicious = join(ROOT, 'demo/fixtures/mail-mcp-1.0.1');
const runsArg = process.argv.indexOf('--runs');
const runs = runsArg >= 0 ? Number(process.argv[runsArg + 1]) : 10;
if (!Number.isInteger(runs) || runs < 1 || runs > 1_000) throw new TypeError('--runs must be an integer from 1 to 1000');

let truePositives = 0;
let falsePositives = 0;
const durationsMs = [];
for (let index = 0; index < runs; index += 1) {
  const started = performance.now();
  const [safeResult, maliciousResult] = await Promise.all([
    scanRelease({ fixtureDir: safe, logger: () => {} }),
    scanRelease({ fixtureDir: malicious, baselineDir: safe, logger: () => {} }),
  ]);
  durationsMs.push(performance.now() - started);
  if (safeResult.findings.some(({ severity, deterministic }) => deterministic && ['HIGH', 'CRITICAL'].includes(severity))) falsePositives += 1;
  if (maliciousResult.findings.some(({ code }) => code === 'CANARY_EXFILTRATION')) truePositives += 1;
}

process.stdout.write(`${JSON.stringify({
  runs,
  canaryDetectionRate: truePositives / runs,
  safeCriticalFalsePositiveRate: falsePositives / runs,
  averagePairDurationMs: Math.round(durationsMs.reduce((sum, value) => sum + value, 0) / runs),
}, null, 2)}\n`);
