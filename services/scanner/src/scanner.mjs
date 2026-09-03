import { createHash, randomUUID } from 'node:crypto';
import { lstat, readFile, readdir } from 'node:fs/promises';
import { extname, relative, resolve, sep } from 'node:path';
import { assertFinding, assertScanResult } from './schema.mjs';
import { runSandbox } from './sandbox.mjs';

const TEXT_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.ts', '.json', '.py']);

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
  return files.sort((a, b) => relative(root, a).localeCompare(relative(root, b)));
}

export async function artifactDigest(root) {
  const hash = createHash('sha256');
  for (const path of await listFiles(root)) {
    hash.update(relative(root, path).split(sep).join('/')).update('\0').update(await readFile(path)).update('\0');
  }
  return `sha256:${hash.digest('hex')}`;
}

async function loadManifest(fixtureDir) {
  const manifest = JSON.parse(await readFile(resolve(fixtureDir, 'manifest.json'), 'utf8'));
  if (typeof manifest.name !== 'string' || typeof manifest.version !== 'string') throw new TypeError('manifest name and version are required');
  if (!Array.isArray(manifest.tools) || !Array.isArray(manifest.declaredEgress)) throw new TypeError('manifest tools and declaredEgress must be arrays');
  if (typeof manifest.entrypoint !== 'string' || !manifest.entrypoint) throw new TypeError('manifest entrypoint is required');
  const entrypoint = resolve(fixtureDir, manifest.entrypoint);
  if (relative(resolve(fixtureDir), entrypoint).startsWith('..')) throw new TypeError('manifest entrypoint escapes fixture directory');
  return manifest;
}

export function toolSurfaceHash(tools) {
  const normalized = [...tools].sort((a, b) => String(a.name).localeCompare(String(b.name)));
  return `0x${createHash('sha256').update(canonicalJson(normalized)).digest('hex')}`;
}

async function sourceFiles(fixtureDir) {
  const files = [];
  for (const path of await listFiles(fixtureDir)) {
    if (!TEXT_EXTENSIONS.has(extname(path))) continue;
    const content = await readFile(path, 'utf8');
    files.push({ path: relative(fixtureDir, path).split(sep).join('/'), content: content.slice(0, 256_000) });
  }
  return files;
}

function staticFindings(files, manifest) {
  const findings = [];
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

export function buildAiPrompt({ releaseId, baselineTools, tools, files }) {
  const excerpts = files.map(({ path, content }) => ({ path, content: content.slice(0, 12_000) }));
  return [
    'Analyze this local demo MCP fixture for semantic behavior mismatches.',
    'Return JSON only: {"findings":[Finding]}. Finding must contain exactly code, severity, deterministic, stage, message, evidence.',
    'Only use code SEMANTIC_BEHAVIOR_MISMATCH, stage AI, and deterministic false. Do not include secrets in evidence.',
    canonicalJson({ releaseId, baselineTools, tools, excerpts }),
  ].join('\n');
}

export async function analyzeSemantics({ url, token, prompt, timeoutMs = 2_000 }) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ prompt }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error(`AI API returned HTTP ${response.status}`);
  const payload = await response.json();
  if (!payload || !Array.isArray(payload.findings)) throw new TypeError('AI API response must contain findings');
  return payload.findings.map((finding) => {
    assertFinding(finding);
    if (finding.code !== 'SEMANTIC_BEHAVIOR_MISMATCH' || finding.stage !== 'AI' || finding.deterministic !== false) {
      throw new TypeError('AI finding violates semantic analyzer policy');
    }
    return finding;
  });
}

export async function scanRelease({
  fixtureDir,
  baselineDir,
  sandbox = 'local',
  sandboxTimeoutMs = 3_000,
  aiUrl,
  aiToken,
  aiTimeoutMs = 2_000,
  source = 'LIVE',
  logger = (event) => process.stderr.write(`${JSON.stringify(event)}\n`),
} = {}) {
  if (!fixtureDir) throw new TypeError('fixtureDir is required');
  if (!['local', 'docker'].includes(sandbox)) throw new TypeError(`unknown sandbox mode: ${sandbox}`);
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

  const aiPromise = aiUrl
    ? analyzeSemantics({ url: aiUrl, token: aiToken, timeoutMs: aiTimeoutMs, prompt: buildAiPrompt({ releaseId, baselineTools, tools: manifest.tools, files }) })
        .catch((error) => { logger({ event: 'ai_analysis_failed', releaseId, error: error.message }); return []; })
    : Promise.resolve([]);
  const sandboxPromise = runSandbox({ mode: sandbox, fixtureDir: fixtureRoot, entrypoint: manifest.entrypoint, timeoutMs: sandboxTimeoutMs })
    .catch((error) => ({ error: error.message, timedOut: false, canaryObserved: false, mode: sandbox.toUpperCase() }));
  const [aiFindings, sandboxResult] = await Promise.all([aiPromise, sandboxPromise]);
  findings.push(...aiFindings);
  if (sandboxResult.canaryObserved) findings.push({
    code: 'CANARY_EXFILTRATION', severity: 'CRITICAL', deterministic: true, stage: 'SANDBOX',
    message: 'The fixture sent the injected dummy canary to the controlled local sink.',
    evidence: { canarySha256: sandboxResult.canaryHash, sink: 'CONTROLLED_LOCAL', sandbox: sandboxResult.mode },
  });
  const sandboxIncomplete = sandboxResult.timedOut || Boolean(sandboxResult.error);
  if (sandboxIncomplete) logger({
    event: sandboxResult.timedOut ? 'sandbox_timeout' : 'sandbox_failed',
    releaseId,
    sandbox: sandboxResult.mode,
    error: sandboxResult.error ?? 'timeout',
  });
  findings.forEach(assertFinding);
  const result = {
    schemaVersion: '1.0.0',
    scanId: randomUUID(),
    releaseId,
    artifactDigest: digest,
    toolSurfaceHash: surfaceHash,
    scanStatus: sandboxIncomplete ? 'INCONCLUSIVE' : findings.some((finding) => finding.deterministic && ['HIGH', 'CRITICAL'].includes(finding.severity)) ? 'FAILED' : 'PASSED',
    findings,
    evidenceHash: `0x${createHash('sha256').update(canonicalJson(findings)).digest('hex')}`,
    source,
  };
  return assertScanResult(result);
}
