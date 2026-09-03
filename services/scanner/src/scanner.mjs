import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdtemp, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { extname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { assertFinding, assertScanResult } from './schema.mjs';
import { assertCanonicalScanResult } from './protocol-schema.mjs';
import { runSandbox } from './sandbox.mjs';
import { copyFixtureSnapshot, removeFixtureSnapshot } from './snapshot.mjs';
import { importPolicyIssues } from '../../../packages/artifact-policy/import-policy.mjs';

const TEXT_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.ts', '.json', '.py']);
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
const MAX_ARTIFACT_FILES = 1_024;
const RELEASE_NAME = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const SEMVER = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
};

async function listFiles(root, current = root) {
  const files = [];
  for (const entry of await readdir(current, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const path = resolve(current, entry.name);
    const stat = await lstat(path);
    if (stat.isSymbolicLink()) throw new Error(`fixture symlinks are not allowed: ${relative(root, path)}`);
    if (stat.isDirectory()) files.push(...await listFiles(root, path));
    else if (stat.isFile()) files.push(path);
  }
  return files.sort((a, b) => {
    const left = relative(root, a).split(sep).join('/');
    const right = relative(root, b).split(sep).join('/');
    return left < right ? -1 : left > right ? 1 : 0;
  });
}

export async function artifactDigest(root) {
  const hash = createHash('sha256');
  const files = await listFiles(root);
  if (files.length > MAX_ARTIFACT_FILES) throw new Error(`fixture exceeds ${MAX_ARTIFACT_FILES} files`);
  let totalBytes = 0;
  for (const path of files) {
    const content = await readFile(path);
    totalBytes += content.byteLength;
    if (totalBytes > MAX_ARTIFACT_BYTES) throw new Error(`fixture exceeds ${MAX_ARTIFACT_BYTES} bytes`);
    hash.update(relative(root, path).split(sep).join('/')).update('\0').update(content).update('\0');
  }
  return `sha256:${hash.digest('hex')}`;
}

async function loadManifest(fixtureDir) {
  const manifest = JSON.parse(await readFile(resolve(fixtureDir, 'manifest.json'), 'utf8'));
  if (!RELEASE_NAME.test(manifest.name) || !SEMVER.test(manifest.version)) throw new TypeError('manifest name or version is not canonical');
  if (!Array.isArray(manifest.tools) || !Array.isArray(manifest.declaredEgress)) throw new TypeError('manifest tools and declaredEgress must be arrays');
  if (manifest.tools.length > 128 || manifest.declaredEgress.length > 128) throw new TypeError('manifest array limit exceeded');
  const toolNames = new Set();
  for (const tool of manifest.tools) {
    if (!tool || typeof tool !== 'object' || typeof tool.name !== 'string' || !tool.name.trim()) throw new TypeError('each tool requires a name');
    if (toolNames.has(tool.name)) throw new TypeError(`duplicate tool name: ${tool.name}`);
    toolNames.add(tool.name);
  }
  if (!manifest.declaredEgress.every((entry) => typeof entry === 'string' && entry.length > 0 && entry.length <= 255)) {
    throw new TypeError('declaredEgress entries must be non-empty strings');
  }
  if (typeof manifest.entrypoint !== 'string' || !manifest.entrypoint) throw new TypeError('manifest entrypoint is required');
  const entrypoint = resolve(fixtureDir, manifest.entrypoint);
  const entrypointRelative = relative(resolve(fixtureDir), entrypoint);
  if (!entrypointRelative || isAbsolute(entrypointRelative) || entrypointRelative.startsWith(`..${sep}`) || entrypointRelative === '..') {
    throw new TypeError('manifest entrypoint escapes fixture directory');
  }
  return manifest;
}

export function toolSurfaceHash(tools) {
  const normalized = [...tools].sort((a, b) => {
    const left = `${String(a.name)}\0${canonicalJson(a)}`;
    const right = `${String(b.name)}\0${canonicalJson(b)}`;
    return left < right ? -1 : left > right ? 1 : 0;
  });
  return `0x${createHash('sha256').update(canonicalJson(normalized)).digest('hex')}`;
}

async function sourceFiles(fixtureDir) {
  const files = [];
  for (const path of await listFiles(fixtureDir)) {
    if (!TEXT_EXTENSIONS.has(extname(path))) continue;
    const content = await readFile(path, 'utf8');
    files.push({ path: relative(fixtureDir, path).split(sep).join('/'), content });
  }
  return files;
}

function staticFindings(files, manifest) {
  const findings = [];
  const importIssue = importPolicyIssues(files)[0];
  if (importIssue) findings.push({
    code: 'UNSAFE_MODULE_LOAD', severity: 'HIGH', deterministic: true, stage: 'STATIC',
    message: 'Artifact module loading is not self-contained.',
    evidence: { file: importIssue.path, rule: 'self-contained-imports-v1', reason: importIssue.reason },
  });
  const sensitive = files.find(({ content }) => /(?:readFile|readFileSync)[\s\S]{0,160}(?:MCP_CANARY_PATH|\.ssh|\.env)/.test(content));
  if (sensitive) findings.push({
    code: 'SENSITIVE_FILE_READ', severity: 'HIGH', deterministic: true, stage: 'STATIC',
    message: 'Fixture reads a sensitive or injected canary file.',
    evidence: { file: sensitive.path, rule: 'sensitive-file-read-v1' },
  });
  const network = files.find(({ content }) => /from\s+['"]node:https?['"]|require\(['"]node:https?['"]\)|\bfetch\s*\(/.test(content));
  if (network && manifest.declaredEgress.length === 0) findings.push({
    code: 'UNDECLARED_EGRESS', severity: 'HIGH', deterministic: true, stage: 'STATIC',
    message: 'Fixture contains network egress while declaring no egress.',
    evidence: { file: network.path, rule: 'undeclared-egress-v1' },
  });
  return findings;
}

function redactPromptText(content) {
  return content
    .replace(/-----BEGIN [^-]+ PRIVATE KEY-----[\s\S]*?-----END [^-]+ PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]')
    .replace(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, '[REDACTED_ACCESS_KEY]')
    .replace(/\bAIza[0-9A-Za-z_-]{35}\b/g, '[REDACTED_GCP_API_KEY]')
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, '[REDACTED_GITHUB_TOKEN]')
    .replace(/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g, '[REDACTED_JWT]')
    .replace(/\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|sk_(?:live|test)_[A-Za-z0-9]{12,}|npm_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b/g, '[REDACTED_TOKEN]')
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+\/-]{12,}/gi, '$1[REDACTED]')
    .replace(/(["'])(password|passwd|secret|token|access[_-]?token|refresh[_-]?token|client[_-]?secret|api[_-]?key|private[_-]?key|authorization|credential)\1\s*:\s*(["'])([^\r\n]{4,}?)\3/gi,
      (_match, keyQuote, key, valueQuote) => `${keyQuote}${key}${keyQuote}:${valueQuote}[REDACTED]${valueQuote}`)
    .replace(/\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*(['"])[^'"\r\n]{4,}\2/gi, '$1=$2[REDACTED]$2')
    .replace(/MCP_SHIELD_DEMO_CANARY_v1/g, '[REDACTED_CANARY]');
}

function sanitizeUntrustedEvidence(value, depth = 0, key = '') {
  if (/password|passwd|secret|token|api.?key|canary|authorization|credential|private.?key/i.test(key)) return '[REDACTED]';
  if (depth > 4) return '[TRUNCATED]';
  if (typeof value === 'string') return redactPromptText(value).slice(0, 512);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 32).map((item) => sanitizeUntrustedEvidence(item, depth + 1));
  if (value && typeof value === 'object') {
    const output = {};
    for (const [childKey, childValue] of Object.entries(value).slice(0, 64)) {
      if (['__proto__', 'prototype', 'constructor'].includes(childKey)) continue;
      output[childKey.slice(0, 128)] = sanitizeUntrustedEvidence(childValue, depth + 1, childKey);
    }
    return output;
  }
  return String(value).slice(0, 128);
}

function promptFileContent(path, content) {
  if (extname(path).toLowerCase() !== '.json') return redactPromptText(content);
  try {
    return canonicalJson(sanitizeUntrustedEvidence(JSON.parse(content)));
  } catch {
    return '[OMITTED_INVALID_JSON]';
  }
}

export function analyzeSemanticsFallback({ manifest, baselineTools = [], files }) {
  const combined = files.map(({ content }) => content).join('\n');
  const signals = [];
  if (/(?:readFile|readFileSync)/.test(combined) && /MCP_CANARY_PATH|\.ssh|\.env/.test(combined)) signals.push('sensitive-file-access');
  if (/from\s+['"]node:https?['"]|require\(['"]node:https?['"]\)|\bfetch\s*\(/.test(combined) && manifest.declaredEgress.length === 0) signals.push('undeclared-network-egress');
  if (baselineTools.length && toolSurfaceHash(baselineTools) !== toolSurfaceHash(manifest.tools)) signals.push('tool-surface-change');
  if (!signals.includes('sensitive-file-access') || !signals.includes('undeclared-network-egress')) return [];
  const finding = {
    code: 'SEMANTIC_BEHAVIOR_MISMATCH',
    severity: 'HIGH',
    deterministic: false,
    stage: 'AI',
    message: 'Local semantic fallback found behavior that exceeds the declared MCP capability.',
    evidence: { analyzer: 'LOCAL_STRUCTURED_FALLBACK_V1', signals: signals.sort() },
  };
  assertFinding(finding);
  return [finding];
}

export function buildAiPrompt({ releaseId, baselineTools, tools, files }) {
  let remaining = 64 * 1024;
  const excerpts = [];
  for (const { path, content } of files) {
    if (remaining <= 0) break;
    const sanitized = promptFileContent(path, content);
    const excerpt = sanitized.slice(0, Math.min(12_000, remaining));
    excerpts.push({ path, content: excerpt });
    remaining -= excerpt.length;
  }
  return [
    'Analyze this local demo MCP fixture for semantic behavior mismatches.',
    'Return JSON only: {"findings":[Finding]}. Finding must contain exactly code, severity, deterministic, stage, message, evidence.',
    'Only use code SEMANTIC_BEHAVIOR_MISMATCH, stage AI, and deterministic false. Do not include secrets in evidence.',
    canonicalJson({ releaseId, baselineTools, tools, excerpts }),
  ].join('\n');
}

async function limitedJson(response, maxBytes = 256 * 1024) {
  if (!response.body) throw new TypeError('AI API returned an empty body');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      throw new TypeError('AI API response exceeds 256 KiB');
    }
    chunks.push(value);
  }
  try { return JSON.parse(Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString('utf8')); }
  catch { throw new TypeError('AI API returned invalid JSON'); }
}

function runtimeFindings(observations, manifest) {
  const findings = [];
  if (observations.some(({ type, target }) => type === 'FS_READ' && target === 'INJECTED_CANARY')) findings.push({
    code: 'SENSITIVE_FILE_READ', severity: 'HIGH', deterministic: true, stage: 'SANDBOX',
    message: 'The fixture read the injected sensitive canary file at runtime.',
    evidence: { observer: 'NODE_PRELOAD_V1', target: 'INJECTED_CANARY' },
  });
  const network = observations.find(({ type, hostname }) => type === 'NETWORK' && hostname && hostname !== 'unknown');
  if (network && manifest.declaredEgress.length === 0) findings.push({
    code: 'UNDECLARED_EGRESS', severity: 'HIGH', deterministic: true, stage: 'SANDBOX',
    message: 'The fixture opened a network connection while declaring no egress.',
    evidence: {
      observer: 'NODE_PRELOAD_V1',
      protocol: network.protocol,
      destination: ['127.0.0.1', 'localhost', 'exfil-sink', '::1'].includes(network.hostname) ? 'CONTROLLED_LOCAL' : network.hostname,
      path: network.path,
    },
  });
  const child = observations.find(({ type }) => type === 'CHILD_PROCESS');
  if (child) findings.push({
    code: 'SEMANTIC_BEHAVIOR_MISMATCH', severity: 'HIGH', deterministic: true, stage: 'SANDBOX',
    message: 'The fixture launched a child process during sandbox execution.',
    evidence: { observer: 'NODE_PRELOAD_V1', command: child.command, method: child.method },
  });
  return findings;
}

export async function analyzeSemantics({ url, token, prompt, timeoutMs = 2_000 }) {
  const endpoint = new URL(url);
  const loopback = ['127.0.0.1', 'localhost', '::1'].includes(endpoint.hostname);
  if (!['http:', 'https:'].includes(endpoint.protocol) || (endpoint.protocol !== 'https:' && !loopback)) {
    throw new TypeError('AI API must use HTTPS or loopback HTTP');
  }
  if (endpoint.username || endpoint.password) throw new TypeError('AI API URL must not include credentials');
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ prompt }),
    signal: AbortSignal.timeout(timeoutMs),
    redirect: 'error',
  });
  if (!response.ok) throw new Error(`AI API returned HTTP ${response.status}`);
  const payload = await limitedJson(response);
  if (!payload || !Array.isArray(payload.findings)) throw new TypeError('AI API response must contain findings');
  return payload.findings.map((finding) => {
    assertFinding(finding);
    if (finding.code !== 'SEMANTIC_BEHAVIOR_MISMATCH' || finding.stage !== 'AI' || finding.deterministic !== false) {
      throw new TypeError('AI finding violates semantic analyzer policy');
    }
    const sanitized = {
      ...finding,
      message: redactPromptText(finding.message).slice(0, 1_000),
      evidence: sanitizeUntrustedEvidence(finding.evidence),
    };
    assertFinding(sanitized);
    return sanitized;
  });
}

async function scanSnapshotRelease({
  fixtureDir,
  baselineDir,
  sandbox = 'local',
  sandboxTimeoutMs = 3_000,
  aiUrl,
  aiToken,
  aiTimeoutMs = 2_000,
  allowRemoteAi = false,
  source = 'LIVE',
  logger = (event) => process.stderr.write(`${JSON.stringify(event)}\n`),
} = {}) {
  if (!fixtureDir) throw new TypeError('fixtureDir is required');
  if (!['local', 'docker'].includes(sandbox)) throw new TypeError(`unknown sandbox mode: ${sandbox}`);
  if (!['LIVE', 'MOCK', 'REPLAY'].includes(source)) throw new TypeError(`unknown scan source: ${source}`);
  for (const [name, value] of [['sandboxTimeoutMs', sandboxTimeoutMs], ['aiTimeoutMs', aiTimeoutMs]]) {
    if (!Number.isFinite(value) || value <= 0) throw new TypeError(`${name} must be a positive number`);
  }
  const fixtureRoot = resolve(fixtureDir);
  const [manifest, files, digest] = await Promise.all([
    loadManifest(fixtureRoot), sourceFiles(fixtureRoot), artifactDigest(fixtureRoot),
  ]);
  const releaseId = `${manifest.name}@${manifest.version}`;
  const surfaceHash = toolSurfaceHash(manifest.tools);
  let baselineTools = [];
  const findings = staticFindings(files, manifest);
  if (baselineDir) {
    const baseline = await loadManifest(resolve(baselineDir));
    baselineTools = baseline.tools;
    const baselineHash = toolSurfaceHash(baseline.tools);
    if (baselineHash !== surfaceHash) findings.push({
      code: 'TOOL_SURFACE_CHANGED', severity: 'MEDIUM', deterministic: true, stage: 'STATIC',
      message: 'The declared MCP tool surface changed from the baseline release.',
      evidence: { baselineToolSurfaceHash: baselineHash, currentToolSurfaceHash: surfaceHash },
    });
  }

  const fallbackInput = { manifest, baselineTools, files };
  if (aiUrl && !allowRemoteAi) logger({
    event: 'ai_remote_disabled', releaseId, fallback: 'LOCAL_STRUCTURED_FALLBACK_V1',
  });
  const aiPromise = aiUrl && allowRemoteAi
    ? analyzeSemantics({ url: aiUrl, token: aiToken, timeoutMs: aiTimeoutMs, prompt: buildAiPrompt({ releaseId, baselineTools, tools: manifest.tools, files }) })
        .catch((error) => {
          logger({ event: 'ai_analysis_failed', releaseId, error: error.message, fallback: 'LOCAL_STRUCTURED_FALLBACK_V1' });
          return analyzeSemanticsFallback(fallbackInput);
        })
    : Promise.resolve(analyzeSemanticsFallback(fallbackInput));
  const sandboxPromise = runSandbox({ mode: sandbox, fixtureDir: fixtureRoot, entrypoint: manifest.entrypoint, timeoutMs: sandboxTimeoutMs })
    .catch((error) => ({ error: error.message, timedOut: false, canaryObserved: false, mode: sandbox.toUpperCase(), observations: [] }));
  const [aiFindings, sandboxResult] = await Promise.all([aiPromise, sandboxPromise]);
  findings.push(...aiFindings);
  const observations = sandboxResult.observations ?? [];
  findings.push(...runtimeFindings(observations, manifest));
  logger({
    event: 'sandbox_observations',
    releaseId,
    sandbox: sandboxResult.mode,
    counts: {
      fsRead: observations.filter(({ type }) => type === 'FS_READ').length,
      network: observations.filter(({ type }) => type === 'NETWORK').length,
      childProcess: observations.filter(({ type }) => type === 'CHILD_PROCESS').length,
    },
  });
  if (sandboxResult.canaryObserved) findings.push({
    code: 'CANARY_EXFILTRATION', severity: 'CRITICAL', deterministic: true, stage: 'SANDBOX',
    message: 'The fixture sent the injected dummy canary to the controlled local sink.',
    evidence: { canarySha256: sandboxResult.canaryHash, sink: 'CONTROLLED_LOCAL', sandbox: sandboxResult.mode },
  });
  let sandboxIncomplete = sandboxResult.timedOut || Boolean(sandboxResult.error);
  try {
    const digestAfterExecution = await artifactDigest(fixtureRoot);
    if (digestAfterExecution !== digest) {
      sandboxIncomplete = true;
      logger({ event: 'snapshot_integrity_failed', releaseId, reason: 'content_changed_during_execution' });
    }
  } catch {
    sandboxIncomplete = true;
    logger({ event: 'snapshot_integrity_failed', releaseId, reason: 'snapshot_unreadable_after_execution' });
  }
  if (sandboxIncomplete) logger({
    event: sandboxResult.timedOut ? 'sandbox_timeout' : 'sandbox_failed',
    releaseId,
    sandbox: sandboxResult.mode,
    error: sandboxResult.error ?? 'timeout',
  });
  findings.forEach(assertFinding);
  const blockingFinding = findings.some((finding) => finding.deterministic && ['HIGH', 'CRITICAL'].includes(finding.severity));
  const canonicalEvidence = [...findings].sort((left, right) => {
    const leftJson = canonicalJson(left);
    const rightJson = canonicalJson(right);
    return leftJson < rightJson ? -1 : leftJson > rightJson ? 1 : 0;
  });
  const result = {
    schemaVersion: '1.0.0',
    scanId: randomUUID(),
    releaseId,
    artifactDigest: digest,
    toolSurfaceHash: surfaceHash,
    scanStatus: blockingFinding ? 'FAILED' : sandboxIncomplete ? 'INCONCLUSIVE' : 'PASSED',
    findings,
    evidenceHash: `0x${createHash('sha256').update(canonicalJson(canonicalEvidence)).digest('hex')}`,
    source,
  };
  assertScanResult(result);
  return assertCanonicalScanResult(result);
}

export async function scanRelease(options = {}) {
  if (!options.fixtureDir) throw new TypeError('fixtureDir is required');
  const logger = options.logger ?? ((event) => process.stderr.write(`${JSON.stringify(event)}\n`));
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-snapshot-'));
  try {
    const fixture = await copyFixtureSnapshot(options.fixtureDir, resolve(workspace, 'fixture'));
    const baseline = options.baselineDir
      ? await copyFixtureSnapshot(options.baselineDir, resolve(workspace, 'baseline'))
      : null;
    logger({
      event: 'snapshot_created',
      fixture: { files: fixture.files, bytes: fixture.bytes },
      ...(baseline ? { baseline: { files: baseline.files, bytes: baseline.bytes } } : {}),
    });
    return await scanSnapshotRelease({
      ...options,
      fixtureDir: fixture.root,
      baselineDir: baseline?.root,
      logger,
    });
  } finally {
    await removeFixtureSnapshot(workspace);
    logger({ event: 'snapshot_removed' });
  }
}
