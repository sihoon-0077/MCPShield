import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { metadataSignals } from '../services/scanner/src/analysis.mjs';

export const MCPToxSource = Object.freeze({ repository: 'https://github.com/zhiqiangwang4/MCPTox-Benchmark',
  commit: 'f85189f9ad12504c197c7f920ab818a40657b1fa', path: 'pure_tool.json',
  sha256: '54b1eb0e9d7b2f18465266aa9d9dfda828cd558b1269b74731ec2c5d8579e617',
  license: 'NO_EXPLICIT_LICENSE_FOUND', verifiedDate: '2026-09-09', rawDataRedistributed: false });
const MAX_BYTES = 1024 * 1024;

export function evaluateMcptoxMetadata(bytes, { requirePinned = true } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_BYTES) throw new TypeError('MCPTox data must be a bounded JSON buffer');
  const hash = createHash('sha256').update(bytes).digest('hex');
  if (requirePinned && hash !== MCPToxSource.sha256) throw new TypeError('MCPTox source hash mismatch');
  let groups;
  try { groups = JSON.parse(bytes); } catch { throw new TypeError('MCPTox dataset is not valid JSON'); }
  if (!Array.isArray(groups) || groups.length > 128 || groups.some((group) => !group || typeof group !== 'object' || Array.isArray(group))) throw new TypeError('MCPTox group shape is invalid');
  const records = groups.flatMap((group) => Object.values(group));
  if (!records.length || records.length > 4096) throw new TypeError('MCPTox record count is invalid');
  const byParadigm = {};
  let detected = 0;
  const started = performance.now();
  for (const row of records) {
    if (typeof row?.tool_name !== 'string' || typeof row?.tool_content !== 'string' || row.tool_content.length > 64 * 1024) throw new TypeError('MCPTox tool record is invalid');
    const review = metadataSignals([{ name: row.tool_name, description: row.tool_content }]).length > 0;
    detected += Number(review);
    const category = ['Template-1', 'Template-2', 'Template-3'].includes(row.paradigm) ? row.paradigm : 'UNKNOWN';
    const bucket = byParadigm[category] ??= { samples: 0, detected: 0 };
    bucket.samples++; bucket.detected += Number(review);
  }
  return { status: 'MEASURED', defense: 'STATIC_METADATA_REVIEW', source: requirePinned ? MCPToxSource : { kind: 'SYNTHETIC_TEST_INPUT' },
    datasetHash: `sha256:${hash}`, sampleSize: records.length, sampleUnit: 'POISONED_TOOL_RECORD_NOT_AGENT_INSTANCE', sourceField: 'tool_content',
    reviewDetected: detected, reviewMissed: records.length - detected, reviewRecall: detected / records.length,
    falsePositiveRate: null, agentAsr: null, byParadigm, latencyMs: performance.now() - started,
    limitations: ['Upstream poisoned-tool labels are not independently relabeled by this project.', 'No benign denominator: FPR is unmeasured, not zero.',
      'Text review signals, not artifact execution, agent ASR or permanent revocation decisions.', 'No upstream payloads are included in this output.'] };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { values } = parseArgs({ options: { input: { type: 'string' } } });
    if (!values.input) throw new TypeError('Provide --input pointing to a separately obtained pinned pure_tool.json; upstream data is not bundled.');
    const chunks = [];
    for await (const chunk of createReadStream(values.input, { start: 0, end: MAX_BYTES })) chunks.push(chunk);
    const report = evaluateMcptoxMetadata(Buffer.concat(chunks));
    let commit = 'UNAVAILABLE';
    try { commit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8', windowsHide: true }).trim(); } catch { /* source archive */ }
    process.stdout.write(JSON.stringify({ ...report, commit, runtime: process.version, platform: process.platform, measuredAt: new Date().toISOString() }, null, 2) + '\n');
  } catch {
    process.stderr.write(JSON.stringify({ status: 'NOT_MEASURED', reason: 'MCPTox benchmark input missing, invalid, oversized or not the pinned dataset',
      source: MCPToxSource, action: 'Obtain the source file separately under applicable permissions; pass --input. Do not redistribute raw data without confirmed rights.' }) + '\n');
    process.exitCode = 1;
  }
}
