import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { metadataSignals } from '../services/scanner/src/analysis.mjs';

const bytes = await readFile(new URL('./metadata-corpus.json', import.meta.url));
const corpus = JSON.parse(bytes);
const started = performance.now();
const matrix = { truePositives: 0, trueNegatives: 0, falsePositives: 0, falseNegatives: 0 };
const results = corpus.cases.map((item) => {
  const signals = metadataSignals([{ name: item.id, description: item.description }]);
  const expected = item.label !== 'BENIGN';
  const detected = signals.length > 0;
  matrix[expected ? detected ? 'truePositives' : 'falseNegatives' : detected ? 'falsePositives' : 'trueNegatives']++;
  return { id: item.id, label: item.label, reviewDetected: detected, categories: [...new Set(signals.map(({ category }) => category))] };
});
const denominator = (a, b) => a + b ? a / (a + b) : null;
let commit = 'unavailable';
try { commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8', windowsHide: true }).trim(); } catch { /* source archive */ }
process.stdout.write(`${JSON.stringify({ status: 'measured', defense: 'STATIC_METADATA_REVIEW', corpusVersion: corpus.version,
  datasetHash: `sha256:${createHash('sha256').update(bytes).digest('hex')}`, sampleSize: results.length, commit,
  runtime: process.version, platform: process.platform, model: 'NONE', prompt: 'NONE', matrix,
  recall: denominator(matrix.truePositives, matrix.falseNegatives), precision: denominator(matrix.truePositives, matrix.falsePositives),
  falsePositiveRate: denominator(matrix.falsePositives, matrix.trueNegatives), latencyMs: performance.now() - started, results,
  limitations: ['Synthetic small corpus, not an external benchmark.', 'Review signals do not authorize revocation.', 'Implicit scope mismatch remains a known lexical blind spot.', corpus.labeling],
}, null, 2)}\n`);
