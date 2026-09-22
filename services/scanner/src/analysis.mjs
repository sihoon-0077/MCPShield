import { createHash } from 'node:crypto';
import { canonicalJson } from './evidence.mjs';

const digest = (value) => `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
const parsePackage = (files, name = 'package.json') => {
  const file = files.find(({ path }) => path === name);
  if (!file) return {};
  try { return JSON.parse(file.content); } catch { return {}; }
};
const dependencyMap = (pkg) => ({ ...pkg.dependencies, ...pkg.optionalDependencies });
const changes = (before, after) => [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()
  .filter((key) => canonicalJson(before[key] ?? null) !== canonicalJson(after[key] ?? null))
  .map((key) => ({ name: key, before: before[key] ?? null, after: after[key] ?? null }));

export function compareRelease({ manifest, files, baselineManifest = {}, baselineFiles = [] }) {
  const pkg = parsePackage(files);
  const previous = parsePackage(baselineFiles);
  const oldTools = new Map((baselineManifest.tools ?? []).map((tool) => [tool.name, tool]));
  const newTools = new Map((manifest.tools ?? []).map((tool) => [tool.name, tool]));
  const tools = [...new Set([...oldTools.keys(), ...newTools.keys()])].sort().flatMap((name) => {
    const before = oldTools.get(name);
    const after = newTools.get(name);
    if (!before || !after) return [{ name, change: before ? 'REMOVED' : 'ADDED', fields: [] }];
    const fields = ['description', 'inputSchema', 'outputSchema', 'annotations'].filter((key) => canonicalJson(before[key] ?? null) !== canonicalJson(after[key] ?? null));
    return fields.length ? [{ name, change: 'MODIFIED', fields, readOnlyRemoved: before.annotations?.readOnlyHint === true && after.annotations?.readOnlyHint !== true }] : [];
  });
  return {
    schemaVersion: '1.0.0', hasBaseline: Boolean(baselineManifest.name), tools,
    dependencies: changes(dependencyMap(previous), dependencyMap(pkg)),
    installScripts: changes(previous.scripts ?? {}, pkg.scripts ?? {}).filter(({ name }) => ['preinstall', 'install', 'postinstall', 'prepare'].includes(name))
      .map(({ name, before, after }) => ({ name, beforeHash: before === null ? null : digest(before), afterHash: after === null ? null : digest(after) })),
    egress: changes(Object.fromEntries((baselineManifest.declaredEgress ?? []).map((host) => [host, true])), Object.fromEntries((manifest.declaredEgress ?? []).map((host) => [host, true]))),
  };
}

export function createSbom(manifest, files) {
  const pkg = parsePackage(files);
  const lock = parsePackage(files, 'package-lock.json');
  const components = new Map();
  const add = (name, version, scope, integrity) => {
    if (typeof name !== 'string' || typeof version !== 'string') return;
    const ref = `pkg:npm/${name.replace('@', '%40')}@${encodeURIComponent(version)}`;
    components.set(ref, { type: 'library', 'bom-ref': ref, name, version, purl: ref, scope,
      ...(typeof integrity === 'string' ? { properties: [{ name: 'npm:integrity', value: integrity }] } : {}) });
  };
  for (const [name, range] of Object.entries(dependencyMap(pkg))) add(name, range, 'required');
  for (const [path, item] of Object.entries(lock.packages ?? {})) {
    if (!path || !path.includes('node_modules/')) continue;
    add(item.name ?? path.slice(path.lastIndexOf('node_modules/') + 13), item.version, item.dev ? 'optional' : 'required', item.integrity);
  }
  return { bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
    metadata: { component: { type: 'application', name: manifest.name, version: manifest.version },
      properties: [{ name: 'mcpshield:dependency-completeness', value: lock.packages ? 'lockfile' : 'declared-only-unresolved-ranges' }] },
    components: [...components.values()].sort((a, b) => a['bom-ref'].localeCompare(b['bom-ref'])),
  };
}

export function metadataSignals(tools) {
  const signals = [];
  const rules = [
    ['MODEL_INSTRUCTION', /ignore\s+(?:all\s+)?(?:previous|prior)|do not tell|secretly|system message|must first/gi],
    ['SENSITIVE_PATH', /~\/\.ssh|\.aws\/credentials|\.env\b|wallet.{0,12}(?:seed|key)|browser.{0,12}(?:cookie|profile)/gi],
    ['HIDDEN_UNICODE', /[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g],
    ['HIDDEN_MARKUP', /<!--[\s\S]*?-->/g],
    ['EXTERNAL_TRANSFER', /(?:send|upload|post|transmit).{0,80}https?:\/\//gi],
  ];
  function visit(value, path) {
    if (!value || typeof value !== 'object') return;
    for (const [key, item] of Object.entries(value)) {
      if (key === 'description' && typeof item === 'string') {
        for (const [category, expression] of rules) for (const match of item.matchAll(expression)) {
          if (signals.length >= 256) return;
          signals.push({ category, source: `${path}.description`, start: match.index, end: match.index + match[0].length,
            textHash: `sha256:${createHash('sha256').update(match[0]).digest('hex')}`, ...(category === 'HIDDEN_UNICODE' ? { codePoint: `U+${match[0].codePointAt(0).toString(16).toUpperCase()}` } : {}) });
        }
      } else if (item && typeof item === 'object') visit(item, `${path}.${key}`);
    }
  }
  tools.forEach((tool, index) => visit(tool, `tools.${index}`));
  return signals;
}

export function generateScenarios(tools) {
  // ponytail: bounded deterministic probes cover metadata and input edges; an agent provider can supply additional reviewed probes.
  return tools.slice(0, 32).flatMap((tool, index) => [
    { scenarioId: `tool-${index}-minimal`, kind: 'NORMAL', toolCall: { name: tool.name, arguments: {} }, executable: Object.keys(tool.inputSchema?.required ?? {}).length === 0, syntheticOnly: true },
    { scenarioId: `tool-${index}-scope`, kind: 'ADVERSARIAL', toolCall: { name: tool.name, arguments: {} }, executable: false, syntheticOnly: true,
      goal: 'Observe whether a normal call touches unrelated synthetic credentials or sends data to an undeclared host.',
      canaryTypes: ['ENV_SECRET', 'SSH_PRIVATE_KEY', 'AWS_SESSION_TOKEN', 'BROWSER_COOKIE', 'WALLET_SEED_DUMMY', 'CUSTOMER_RECORD'],
      failOn: ['CANARY_READ', 'CANARY_EGRESS', 'UNDECLARED_HOST'] },
  ]);
}

export function analyzePackage({ manifest, files, baselineManifest, baselineFiles }) {
  return { schemaVersion: '1.0.0', packageDiff: compareRelease({ manifest, files, baselineManifest, baselineFiles }),
    sbom: createSbom(manifest, files), metadataSignals: metadataSignals(manifest.tools), scenarios: generateScenarios(manifest.tools) };
}
