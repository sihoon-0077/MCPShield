import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import { exactReleaseIdentity } from '../../../packages/contracts-sdk/src/v2-identity.mjs';
import { canonicalJson } from './canonical-json.mjs';
import { validatePreparedReleaseBinding, validatePreparedExecutionPolicy } from './prepared-binding.mjs';
import { checkedScopedProvenance, SCOPED_NODE_PROFILE, validateScopedBaselineReviewPolicy } from './scoped-policy.mjs';
import { toolSurfaceHash } from './tool-surface.mjs';
import { inspectPreparedSources } from './prepared-review.mjs';
import { compareRelease } from './analysis.mjs';
import { hashPreparedRuntimeDescriptor } from '../../resolver/src/runtime-descriptor.mjs';

const hash = (value) => `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join() === [...keys].sort().join();
const same = (first, second) => canonicalJson(first) === canonicalJson(second);
export const SCOPED_BASELINE_TRUST_FIELDS = Object.freeze(['builderImageDigest', 'collectorDigest', 'observerDigest',
  'finalImageDigest', 'platform', 'closureDigest', 'sourceDescriptorDigest', 'entrypointDigest',
  'sourceIdentity', 'sourceProvenance', 'sourceBudget', 'publisher', 'releaseId']);

export function checkedScopedSourceIdentity(value, artifactDigest) {
  if (!exact(value, ['releaseId', 'toolId', 'artifactDigest', 'manifestDigest', 'toolSurfaceHash']) ||
    !/^0x[a-f0-9]{64}$/.test(value.toolId) || !/^sha256:[a-f0-9]{64}$/.test(value.artifactDigest) ||
    !/^sha256:[a-f0-9]{64}$/.test(value.manifestDigest) || !/^0x[a-f0-9]{64}$/.test(value.toolSurfaceHash) ||
    value.artifactDigest !== artifactDigest || exactReleaseIdentity(value).releaseId !== value.releaseId) {
    throw Error('SCOPED_SOURCE_IDENTITY_INVALID');
  }
  return structuredClone(value);
}

// Pure identity commitment, NOT acquisition or proof of approval/authority. The
// caller must independently acquire both sources and runtime exports. No paths,
// publisher manifest/key or retrieval timestamps enter the provider DTO.
export function scopedBaselineCommitment({ sourceIdentity, executionPolicy, baseline }) {
  if (!validatePreparedExecutionPolicy(executionPolicy) || !validateScopedBaselineReviewPolicy(executionPolicy.semantic)) throw Error('SCOPED_BASELINE_POLICY_REQUIRED');
  checkedScopedSourceIdentity(sourceIdentity, sourceIdentity?.artifactDigest);
  if (baseline === null) return null;
  if (!exact(baseline, ['releaseId', 'sourceIdentity', 'binding', 'sourceProvenance'])) throw Error('SCOPED_BASELINE_SELECTION_INVALID');
  const { binding } = baseline;
  if (!validatePreparedReleaseBinding(binding) || binding.executionPolicy.profile !== SCOPED_NODE_PROFILE ||
    binding.executionPolicy.semantic.evidenceMode !== executionPolicy.semantic.evidenceMode) throw Error('SCOPED_BASELINE_BINDING_INVALID');
  const previous = checkedScopedSourceIdentity(baseline.sourceIdentity, binding.sourceArtifactDigest);
  const provenance = checkedScopedProvenance(baseline.sourceProvenance, binding.sourceArtifactDigest);
  const release = exactReleaseIdentity({ toolId: previous.toolId, artifactDigest: binding.artifactDigest,
    manifestDigest: binding.manifestDigest, toolSurfaceHash: binding.toolSurfaceHash });
  if (previous.toolId !== sourceIdentity.toolId || previous.releaseId !== binding.sourceReleaseId ||
    previous.releaseId === sourceIdentity.releaseId || release.releaseId !== baseline.releaseId) throw Error('SCOPED_BASELINE_IDENTITY_MISMATCH');
  return { releaseId: release.releaseId, sourceIdentity: previous, descriptorDigest: binding.descriptorDigest,
    runtimeDigest: binding.finalImageDigest, toolSurfaceHash: binding.toolSurfaceHash,
    executionPolicyDigest: binding.executionPolicyDigest, sourceProvenance: provenance };
}

// A validator must obtain this context itself. A matching report cannot create
// authority. Source/key reacquisition remains the operator/API caller's duty.
export function checkedScopedBaselineAuthority(context, trusted) {
  const commitment = scopedBaselineCommitment(context);
  if (commitment === null) { if (trusted !== null) throw Error('SCOPED_BASELINE_AUTHORITY_MISMATCH'); return null; }
  const { binding, sourceIdentity, sourceProvenance } = context.baseline;
  if (!exact(trusted, SCOPED_BASELINE_TRUST_FIELDS) || trusted.releaseId !== commitment.releaseId || !same(sourceIdentity, trusted.sourceIdentity) ||
    !same(sourceProvenance, checkedScopedProvenance(trusted.sourceProvenance, binding.sourceArtifactDigest)) ||
    !exact(trusted.sourceBudget, ['sourceArtifactDigest', 'sourceBytes']) || trusted.sourceBudget.sourceArtifactDigest !== binding.sourceArtifactDigest ||
    !Number.isSafeInteger(trusted.sourceBudget.sourceBytes) || trusted.sourceBudget.sourceBytes < 0 || trusted.sourceBudget.sourceBytes > 16 * 1024 * 1024 ||
    trusted.builderImageDigest !== binding.descriptor.builderImageDigest || trusted.collectorDigest !== binding.executionPolicy.collectorDigest ||
    trusted.observerDigest !== binding.executionPolicy.observerDigest || trusted.finalImageDigest !== binding.finalImageDigest ||
    !same(trusted.platform, binding.platform) || trusted.entrypointDigest !== binding.descriptor.entrypoint.digest ||
    !/^sha256:[a-f0-9]{64}$/.test(trusted.closureDigest) ||
    trusted.sourceDescriptorDigest !== hashPreparedRuntimeDescriptor({ ...binding.descriptor, stage: 'PREFLIGHT', finalImageDigest: null, toolSurfaceHash: null })) {
    throw Error('SCOPED_BASELINE_AUTHORITY_MISMATCH');
  }
  if (trusted.publisher !== null && (!exact(trusted.publisher, ['manifest', 'verification']) ||
    trusted.publisher.verification?.type !== 'DEMO_PUBLISHER_SIGNATURE_VALID' || trusted.publisher.verification.verified !== true ||
    trusted.publisher.verification.artifactDigest !== binding.sourceArtifactDigest ||
    trusted.publisher.manifest?.payload?.artifactDigest !== binding.sourceArtifactDigest)) throw Error('SCOPED_BASELINE_PUBLISHER_AUTHORITY_INVALID');
  return commitment;
}

export function preparedClosureEvidence(closure) {
  if (closure.bytes > 8 * 1024 * 1024) throw Error('SCOPED_BASELINE_SOURCE_BUDGET_EXCEEDED');
  const review = inspectPreparedSources(closure);
  return { inventory: { ...review.inventory, source: closure.source }, report: closure.report,
    source: { complete: true, files: closure.contents.map(({ path, bytes }) => ({ path, base64: bytes.toString('base64') })) },
    sbom: review.sbom, findings: review.findings };
}

export function readPreparedClosureEvidence(document, binding, trusted) {
  if (!exact(document, ['inventory', 'report', 'source', 'sbom', 'findings']) || document.source?.complete !== true ||
    !Array.isArray(document.source.files) || document.source.files.length > 8192) throw Error('SCOPED_BASELINE_SOURCE_EVIDENCE_INVALID');
  let bytes = 0;
  const contents = document.source.files.map(file => {
    if (!exact(file, ['path', 'base64']) || typeof file.base64 !== 'string' || file.base64.length > Math.ceil(8 * 1024 * 1024 / 3) * 4) throw Error('SCOPED_BASELINE_SOURCE_EVIDENCE_INVALID');
    const content = Buffer.from(file.base64, 'base64'); bytes += content.length;
    if (bytes > 8 * 1024 * 1024 || content.toString('base64') !== file.base64) throw Error('SCOPED_BASELINE_SOURCE_EVIDENCE_INVALID');
    return { path: file.path, bytes: content };
  });
  const { inventory, report } = document, closure = { ...inventory, report, contents };
  const review = inspectPreparedSources(closure);
  if (inventory.source !== 'LIVE_DOCKER_IMAGE_EXPORT' || inventory.entries.length > 8192 || inventory.bytes !== bytes ||
    inventory.digest !== trusted.closureDigest || report.digest !== inventory.digest || report.bytes !== bytes ||
    !same(report.entries, inventory.entries) || report.sourceDescriptorDigest !== trusted.sourceDescriptorDigest ||
    report.installScripts !== false || report.installNetwork !== 'NONE' ||
    !same(inventory, { ...review.inventory, source: inventory.source }) || !same(document.sbom, review.sbom) ||
    !same(document.findings, review.findings) || !review.inventory.staticComplete || !review.sbom.complete || review.issues.length ||
    inventory.entries.find(entry => entry.path === binding.descriptor.entrypoint.path)?.digest !== trusted.entrypointDigest) {
    throw Error('SCOPED_BASELINE_CLOSURE_MISMATCH');
  }
  return { closure, review };
}

export function checkedPreparedBaselineEvidence(document, context, trusted) {
  const commitment = checkedScopedBaselineAuthority(context, trusted);
  if (commitment === null) { if (document !== null) throw Error('SCOPED_BASELINE_EVIDENCE_MISMATCH'); return null; }
  if (!exact(document, ['schemaVersion', 'selection', 'publisher', 'closure', 'tools', 'discovery', 'observedAt']) ||
    document.schemaVersion !== 'mcpshield.prepared-baseline-evidence.v1' || !same(document.selection, context.baseline) ||
    !same(document.publisher, trusted.publisher) || typeof document.observedAt !== 'string' ||
    !Number.isFinite(Date.parse(document.observedAt))) throw Error('SCOPED_BASELINE_EVIDENCE_MISMATCH');
  const { binding } = context.baseline, { closure, review } = readPreparedClosureEvidence(document.closure, binding, trusted);
  const step = document.discovery;
  if (toolSurfaceHash(document.tools) !== binding.toolSurfaceHash || !step || step.protocolComplete !== true || step.timedOut ||
    step.exitCode !== 0 || step.failureCode || !Number.isSafeInteger(step.pages) || step.pages < 1 || step.pages > 32 ||
    step.permissionProfile !== 'NODE_PERMISSION_READ_ONLY_V1' || step.toolSurfaceHash !== binding.toolSurfaceHash ||
    !same(step.runtimeIdentity, { imageDigest: binding.finalImageDigest, platform: binding.platform, argv: binding.descriptor.argv }) ||
    !Array.isArray(step.callResults) || step.callResults.length || step.canaryExfiltration || !Array.isArray(step.egressEvents) ||
    step.egressEvents.some(event => ['EGRESS_BODY_LIMIT', 'EGRESS_BLOCKED'].includes(event.type))) throw Error('SCOPED_BASELINE_DISCOVERY_INCOMPLETE');
  return { closure, review, semanticInput: { ...context.baseline, files: review.files, tools: document.tools, closureDigest: closure.digest } };
}

function installedPackages(closure, review) {
  const packages = new Map(review.sbom.components.map(component => {
    const metadata = Object.fromEntries(component.properties.map(({ name, value }) => [name, value]));
    const root = posix.dirname(metadata['mcpshield:installed-path']);
    return [root, { name: component.name, version: component.version,
      packageJsonDigest: metadata['mcpshield:package-json-digest'], entries: [] }];
  }));
  for (const entry of closure.entries) {
    let root = posix.dirname(entry.path);
    while (!packages.has(root) && root !== '.') root = posix.dirname(root);
    packages.get(root)?.entries.push(entry);
  }
  return new Map([...packages].filter(([root]) => root !== '.').map(([root, { entries, ...item }]) =>
    [root, { ...item, installedContentDigest: hash(entries.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)) }]));
}

// Reuses the existing full inventory/SBOM verifier. These pure bytes may be unit
// fixtures: this result itself never claims LIVE acquisition or grants approval.
export function comparePreparedClosures({ current, tools, executionPolicy, baseline }) {
  if (!validatePreparedExecutionPolicy(executionPolicy) || !validateScopedBaselineReviewPolicy(executionPolicy.semantic)) throw Error('SCOPED_BASELINE_POLICY_REQUIRED');
  const next = inspectPreparedSources(current);
  if (!next.inventory.staticComplete || !next.sbom.complete || next.issues.length) throw Error('SCOPED_COMPARISON_CURRENT_INCOMPLETE');
  toolSurfaceHash(tools);
  if (baseline === null) return { schemaVersion: 'mcpshield.prepared-package-diff.v1', baselineProvided: false,
    comparison: 'NO_BASELINE_NOT_AN_UPDATE_COMPARISON', currentClosureDigest: current.digest, baselineClosureDigest: null,
    tools: [], dependencies: [], installedDependencies: [], installScripts: [], egressPolicy: [] };
  if (!exact(baseline, ['closure', 'tools', 'executionPolicy'])) throw Error('SCOPED_COMPARISON_BASELINE_INVALID');
  if (!validatePreparedExecutionPolicy(baseline.executionPolicy) || baseline.executionPolicy.profile !== SCOPED_NODE_PROFILE ||
    baseline.executionPolicy.semantic.evidenceMode !== executionPolicy.semantic.evidenceMode) throw Error('SCOPED_BASELINE_POLICY_REQUIRED');
  const previous = inspectPreparedSources(baseline.closure);
  if (!previous.inventory.staticComplete || !previous.sbom.complete || previous.issues.length) throw Error('SCOPED_COMPARISON_BASELINE_INCOMPLETE');
  toolSurfaceHash(baseline.tools);
  const diff = compareRelease({ files: next.files, baselineFiles: previous.files,
    manifest: { name: next.sbom.metadata.component.name, tools, declaredEgress: executionPolicy.egressAllowHosts },
    baselineManifest: { name: previous.sbom.metadata.component.name, tools: baseline.tools, declaredEgress: baseline.executionPolicy.egressAllowHosts } });
  const before = installedPackages(baseline.closure, previous), after = installedPackages(current, next);
  const installedDependencies = [...new Set([...before.keys(), ...after.keys()])].sort().flatMap(path =>
    canonicalJson(before.get(path) ?? null) === canonicalJson(after.get(path) ?? null) ? [] :
      [{ path, before: before.get(path) ?? null, after: after.get(path) ?? null }]);
  return { schemaVersion: 'mcpshield.prepared-package-diff.v1', baselineProvided: true,
    comparison: 'INSTALLED_CLOSURE_AND_DISCOVERED_TOOLS', currentClosureDigest: current.digest,
    baselineClosureDigest: baseline.closure.digest, tools: diff.tools, dependencies: diff.dependencies,
    installedDependencies, installScripts: diff.installScripts, egressPolicy: diff.egress };
}

// Projection only: the aggregate must recompute the comparison from both actual
// exports. Hash script bodies/installed paths; every remaining string goes through
// the caller's redaction and the same metadata+source disclosure accounting.
export function checkedScopedComparison(value, currentDigest, baselineDigest) {
  const invalid = () => { throw Error('SCOPED_COMPARISON_INVALID'); };
  const text = value => typeof value === 'string' && value.length > 0 && value.length <= 256;
  const digest = value => /^sha256:[a-f0-9]{64}$/.test(value);
  const arrays = ['tools', 'dependencies', 'installedDependencies', 'installScripts', 'egressPolicy'];
  if (!exact(value, ['schemaVersion', 'baselineProvided', 'comparison', 'currentClosureDigest', 'baselineClosureDigest', ...arrays]) ||
    value.schemaVersion !== 'mcpshield.prepared-package-diff.v1' || value.baselineProvided !== (baselineDigest !== null) ||
    value.currentClosureDigest !== currentDigest || !digest(currentDigest) || value.baselineClosureDigest !== baselineDigest ||
    baselineDigest !== null && !digest(baselineDigest) ||
    value.comparison !== (baselineDigest === null ? 'NO_BASELINE_NOT_AN_UPDATE_COMPARISON' : 'INSTALLED_CLOSURE_AND_DISCOVERED_TOOLS') ||
    arrays.some(key => !Array.isArray(value[key]) || value[key].length > 512 || baselineDigest === null && value[key].length)) invalid();
  for (const row of value.tools) {
    if (!(exact(row, ['name', 'change', 'fields']) || exact(row, ['name', 'change', 'fields', 'readOnlyRemoved'])) ||
      !text(row.name) || !['ADDED', 'REMOVED', 'MODIFIED'].includes(row.change) || !Array.isArray(row.fields) || row.fields.length > 4 ||
      row.fields.some(field => !['description', 'inputSchema', 'outputSchema', 'annotations'].includes(field)) ||
      row.readOnlyRemoved !== undefined && typeof row.readOnlyRemoved !== 'boolean') invalid();
  }
  for (const row of value.dependencies) if (!exact(row, ['name', 'before', 'after']) || !text(row.name) ||
    ![row.before, row.after].every(item => item === null || text(item))) invalid();
  for (const row of value.installScripts) if (!exact(row, ['name', 'beforeHash', 'afterHash']) ||
    !['preinstall', 'install', 'postinstall', 'prepare'].includes(row.name) || ![row.beforeHash, row.afterHash].every(item => item === null || digest(item))) invalid();
  for (const row of value.egressPolicy) if (!exact(row, ['name', 'before', 'after']) || !text(row.name) ||
    ![row.before, row.after].every(item => item === null || item === true)) invalid();
  for (const row of value.installedDependencies) {
    if (!exact(row, ['path', 'before', 'after']) || typeof row.path !== 'string' || !row.path || row.path.length > 1024) invalid();
    for (const item of [row.before, row.after]) if (item !== null && (!exact(item, ['name', 'version', 'packageJsonDigest', 'installedContentDigest']) ||
      !text(item.name) || !text(item.version) || !digest(item.packageJsonDigest) || !digest(item.installedContentDigest))) invalid();
  }
  return { ...structuredClone(value), installedDependencies: value.installedDependencies.map(({ path, ...row }) => ({ packageId: hash(path), ...row })) };
}
