const CODES = new Set([
  'SENSITIVE_FILE_READ',
  'UNDECLARED_EGRESS',
  'CANARY_EXFILTRATION',
  'TOOL_SURFACE_CHANGED',
  'SEMANTIC_BEHAVIOR_MISMATCH',
]);
const SEVERITIES = new Set(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const STAGES = new Set(['STATIC', 'AI', 'SANDBOX', 'POLICY']);
const STATUSES = new Set(['QUEUED', 'RUNNING', 'PASSED', 'FAILED', 'INCONCLUSIVE']);
const SOURCES = new Set(['LIVE', 'MOCK', 'REPLAY']);

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

export function assertFinding(finding) {
  if (!isObject(finding)) throw new TypeError('finding must be an object');
  const keys = Object.keys(finding).sort().join(',');
  if (keys !== 'code,deterministic,evidence,message,severity,stage') {
    throw new TypeError('finding has missing or unknown fields');
  }
  if (!CODES.has(finding.code)) throw new TypeError(`unknown finding code: ${finding.code}`);
  if (!SEVERITIES.has(finding.severity)) throw new TypeError(`unknown severity: ${finding.severity}`);
  if (typeof finding.deterministic !== 'boolean') throw new TypeError('deterministic must be boolean');
  if (!STAGES.has(finding.stage)) throw new TypeError(`unknown stage: ${finding.stage}`);
  if (typeof finding.message !== 'string' || !finding.message.trim()) throw new TypeError('message is required');
  if (!isObject(finding.evidence)) throw new TypeError('evidence must be an object');
  return finding;
}

export function assertScanResult(result) {
  if (!isObject(result)) throw new TypeError('scan result must be an object');
  const required = [
    'schemaVersion', 'scanId', 'releaseId', 'artifactDigest', 'toolSurfaceHash',
    'scanStatus', 'findings', 'evidenceHash', 'source',
  ];
  const keys = Object.keys(result).sort();
  if (keys.join(',') !== [...required].sort().join(',')) throw new TypeError('scan result has missing or unknown fields');
  if (result.schemaVersion !== '1.0.0') throw new TypeError('unsupported schemaVersion');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(result.scanId)) {
    throw new TypeError('invalid scanId');
  }
  if (!/^.+@[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/.test(result.releaseId)) {
    throw new TypeError('invalid releaseId');
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(result.artifactDigest)) throw new TypeError('invalid artifactDigest');
  if (!/^0x[0-9a-f]{64}$/.test(result.toolSurfaceHash)) throw new TypeError('invalid toolSurfaceHash');
  if (!STATUSES.has(result.scanStatus)) throw new TypeError('invalid scanStatus');
  if (!Array.isArray(result.findings)) throw new TypeError('findings must be an array');
  result.findings.forEach(assertFinding);
  if (!/^0x[0-9a-f]{64}$/.test(result.evidenceHash)) throw new TypeError('invalid evidenceHash');
  if (!SOURCES.has(result.source)) throw new TypeError('invalid source');
  return result;
}
