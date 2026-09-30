import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import { exactReleaseIdentity } from '../../../packages/contracts-sdk/src/v2-identity.mjs';
import { canonicalJson } from './canonical-json.mjs';
import { validatePreparedReleaseBinding, validatePreparedExecutionPolicy } from './prepared-binding.mjs';
import { checkedScopedProvenance, SCOPED_NODE_PROFILE, validateScopedBaselineReviewPolicy } from './scoped-policy.mjs';
import { toolSurfaceHash } from './tool-surface.mjs';
import { inspectPreparedSources } from './prepared-review.mjs';
import { compareRelease } from './analysis.mjs';

const hash = (value) => `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join() === [...keys].sort().join();

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
