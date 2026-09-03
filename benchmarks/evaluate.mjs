import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRelease } from '../services/scanner/src/scanner.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const safe = join(ROOT, 'demo/fixtures/mail-mcp-1.0.0');
const malicious = join(ROOT, 'demo/fixtures/mail-mcp-1.0.1');
const runsArg = process.argv.indexOf('--runs');
const runs = runsArg >= 0 ? Number(process.argv[runsArg + 1]) : 10;
const sandboxArg = process.argv.indexOf('--sandbox');
const sandbox = sandboxArg >= 0 ? process.argv[sandboxArg + 1] : 'local';
if (!Number.isInteger(runs) || runs < 1 || runs > 1_000) throw new TypeError('--runs must be an integer from 1 to 1000');
if (!['local', 'docker'].includes(sandbox)) throw new TypeError('--sandbox must be local or docker');

let truePositives = 0;
let trueNegatives = 0;
let falsePositives = 0;
let falseNegatives = 0;
let canaryDetections = 0;
const safeDurationsMs = [];
const maliciousDurationsMs = [];
const isBlocking = (result) => result.findings.some(({ severity, deterministic }) => deterministic && ['HIGH', 'CRITICAL'].includes(severity));
for (let index = 0; index < runs; index += 1) {
  let started = performance.now();
  const safeResult = await scanRelease({ fixtureDir: safe, sandbox, logger: () => {} });
  safeDurationsMs.push(performance.now() - started);
  started = performance.now();
  const maliciousResult = await scanRelease({ fixtureDir: malicious, baselineDir: safe, sandbox, logger: () => {} });
  maliciousDurationsMs.push(performance.now() - started);
  if (isBlocking(safeResult)) falsePositives += 1;
  else trueNegatives += 1;
  if (isBlocking(maliciousResult)) truePositives += 1;
  else falseNegatives += 1;
  if (maliciousResult.findings.some(({ code }) => code === 'CANARY_EXFILTRATION')) canaryDetections += 1;
}

const percentile = (values, quantile) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(sorted.length * quantile) - 1)];
};
const latency = (values) => ({
  average: Math.round(values.reduce((sum, value) => sum + value, 0) / values.length),
  p50: Math.round(percentile(values, 0.5)),
  p95: Math.round(percentile(values, 0.95)),
  max: Math.round(Math.max(...values)),
});
const recall = truePositives / (truePositives + falseNegatives);
const precision = truePositives + falsePositives === 0 ? 1 : truePositives / (truePositives + falsePositives);
const falsePositiveRate = falsePositives / (falsePositives + trueNegatives);
const report = {
  schemaVersion: '1.0.0',
  source: 'LIVE',
  sandbox: sandbox.toUpperCase(),
  runs,
  confusionMatrix: { truePositives, trueNegatives, falsePositives, falseNegatives },
  recall,
  precision,
  falsePositiveRate,
  canaryDetectionRate: canaryDetections / runs,
  latencyMs: { safe: latency(safeDurationsMs), malicious: latency(maliciousDurationsMs) },
  acceptance: { minimumRecall: 1, maximumFalsePositiveRate: 0 },
  passed: recall === 1 && falsePositiveRate === 0 && canaryDetections === runs,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (!report.passed) process.exitCode = 1;
