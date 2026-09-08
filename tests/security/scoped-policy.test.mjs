import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { canonicalJson } from '../../services/scanner/src/evidence.mjs';
import { SCOPED_NODE_PROFILE, SCOPED_OCI_PROFILE, scopedReviewPolicy, validateScopedReviewPolicy,
  checkedScopedProvenance } from '../../services/scanner/src/scoped-policy.mjs';
import { preparedExecutionPolicy, scopedPreparedExecutionPolicy, validatePreparedExecutionPolicy } from '../../services/scanner/src/prepared-binding.mjs';
import { ociExecutionPolicy, scopedOciExecutionPolicy, validateOciExecutionPolicy } from '../../services/scanner/src/oci-binding.mjs';

const hash = (value) => 'sha256:' + createHash('sha256').update(canonicalJson(value)).digest('hex');

test('v2 semantic policy commits exact disclosure/mode/budget/roles while preserving v1 runtime isolation', () => {
  const node = { collectorDigest: hash('collector'), observerDigest: hash('observer'), egressAllowHosts: ['mail-api.local'] };
  const oci = Object.fromEntries(['baseImageDigest', 'baseCatalogueDigest', 'trivyImageDigest', 'databaseDigest',
    'observerDigest', 'sinkImageDigest', 'sinkCodeDigest'].map(field => [field, hash(field)]));
  for (const mode of ['PROVIDER_EXECUTION', 'LOCAL_CONTRACT_TEST']) {
    const semantic = scopedReviewPolicy(mode);
    assert.equal(validateScopedReviewPolicy(semantic), true);
    const n = scopedPreparedExecutionPolicy(node, semantic), o = scopedOciExecutionPolicy(oci, semantic);
    assert.equal(n.profile, SCOPED_NODE_PROFILE); assert.equal(o.profile, SCOPED_OCI_PROFILE);
    assert.equal(validatePreparedExecutionPolicy(n), true); assert.equal(validateOciExecutionPolicy(o), true);
    assert.deepEqual(n.gateway, preparedExecutionPolicy(node).gateway);
    assert.deepEqual(o.gateway, ociExecutionPolicy(oci).gateway);
    assert.notEqual(hash(n), hash(preparedExecutionPolicy(node)));
    assert.notEqual(hash(o), hash(ociExecutionPolicy(oci)));
    for (const mutate of [p => p.semantic.limits.inputBytes++, p => p.semantic.roles.required.pop(),
      p => p.semantic.privacyScope.wholeSource = 'ALLOWED', p => p.semantic.disclosurePolicy = mode,
      p => p.semantic.evidenceMode = 'SCOPED_PROVIDER_REVIEW_V1', p => p.extra = true]) {
      const changedN = structuredClone(n), changedO = structuredClone(o); mutate(changedN); mutate(changedO);
      assert.equal(validatePreparedExecutionPolicy(changedN), false); assert.equal(validateOciExecutionPolicy(changedO), false);
    }
  }
  assert.notEqual(hash(scopedReviewPolicy('LOCAL_CONTRACT_TEST')), hash(scopedReviewPolicy('PROVIDER_EXECUTION')));
  assert.throws(() => scopedReviewPolicy('SCOPED_PROVIDER_REVIEW_V1'), /EVIDENCE_MODE_INVALID/);
});

test('operator provenance is exact-source bound and is never inferred from a package, image or opt-in boolean', () => {
  const sourceArtifactDigest = hash('local immutable source');
  const provenance = { schemaVersion: 'mcpshield.operator-code-artifact.v1', authority: 'OPERATOR_LOCAL_CATALOG',
    contentClass: 'CODE_ARTIFACT_NO_CUSTOMER_DATA', sourceArtifactDigest };
  assert.deepEqual(checkedScopedProvenance(provenance, sourceArtifactDigest), provenance);
  for (const bad of [null, true, {}, { ...provenance, sourceArtifactDigest: hash('other') },
    { ...provenance, authority: 'PACKAGE_DECLARATION' }, { ...provenance, contentClass: 'UNKNOWN' },
    { ...provenance, allowRemoteAi: true }]) assert.throws(() => checkedScopedProvenance(bad, sourceArtifactDigest), /PROVENANCE_REQUIRED/);
});
