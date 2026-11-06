import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPairSync } from 'node:crypto';
import { appendFile, cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveArtifact } from '../../services/resolver/src/resolver.mjs';
import { signDemoPublisherManifest, verifyDemoPublisherManifest } from '../../services/resolver/src/demo-publisher.mjs';

const catalogue = JSON.parse(await readFile(new URL('../../demo/fixtures/publisher-signatures.json', import.meta.url)));
const fixture = (version) => fileURLToPath(new URL(`../../demo/fixtures/mail-mcp-${version}/`, import.meta.url));
const configuration = (version) => ({ publisherId: 'mcpshield-demo-publisher', pinnedPublicKey: catalogue.pinnedPublicKey,
  manifest: catalogue.signatures[version] });
const expected = (version) => ({ publisherId: 'mcpshield-demo-publisher', name: 'mail-mcp', version,
  artifactDigest: catalogue.signatures[version].payload.artifactDigest });

test('one pinned demo publisher authenticates both safe and malicious source bytes, not behavior', async () => {
  const keys = [];
  for (const version of ['1.0.0', '1.0.1']) {
    // Reads/snapshots only: neither fixture executable is launched.
    const resolved = await resolveArtifact({ source: { type: 'local', path: fixture(version) } }, { demoPublisher: configuration(version) });
    try {
      const evidence = resolved.metadata.publisherEvidence.at(-1);
      assert.equal(evidence.type, 'DEMO_PUBLISHER_SIGNATURE_VALID');
      assert.equal(evidence.verified, true);
      assert.equal(evidence.artifactDigest, resolved.artifactDigest);
      assert.equal(evidence.digestKind, resolved.metadata.artifactDigestAlgorithm);
      assert.equal(evidence.purpose, 'DEMO_ONLY_NOT_NPM_PROVENANCE');
      assert.equal(evidence.behaviorSafety, 'NOT_ASSESSED');
      keys.push(evidence.publicKeyFingerprint);
    } finally { await resolved.cleanup(); }
  }
  assert.equal(keys[0], keys[1]);
  assert.notEqual(expected('1.0.0').artifactDigest, expected('1.0.1').artifactDigest);
});

test('configured resolver rejects altered source bytes and missing signature before returning an artifact', async () => {
  const root = await mkdtemp(join(tmpdir(), 'mcpshield-publisher-test-'));
  try {
    await cp(fixture('1.0.0'), root, { recursive: true });
    await appendFile(join(root, 'index.mjs'), '\n// synthetic byte tampering\n');
    await assert.rejects(() => resolveArtifact({ source: { type: 'local', path: root } }, { demoPublisher: configuration('1.0.0') }),
      /DEMO_PUBLISHER_SIGNATURE_OR_IDENTITY_INVALID/);
    for (const manifest of [undefined, null, {}, { payload: catalogue.signatures['1.0.0'].payload }]) {
      await assert.rejects(() => resolveArtifact({ source: { type: 'local', path: fixture('1.0.0') } },
        { demoPublisher: { ...configuration('1.0.0'), manifest } }), /DEMO_PUBLISHER_SIGNATURE_OR_IDENTITY_INVALID/);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('wrong key, substituted identity, broken signature and candidate-provided key cannot authenticate', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const attackerKey = publicKey.export({ type: 'spki', format: 'pem' });
  const base = { manifest: catalogue.signatures['1.0.0'], expectedIdentity: expected('1.0.0'), pinnedPublicKey: catalogue.pinnedPublicKey };
  for (const input of [
    { ...base, pinnedPublicKey: attackerKey },
    { ...base, pinnedPublicKey: undefined },
    { ...base, expectedIdentity: { ...base.expectedIdentity, version: '1.0.1' } },
    { ...base, manifest: { ...base.manifest, signature: 'A'.repeat(86) + '==' } },
    { ...base, manifest: { ...base.manifest, payload: undefined } },
    { ...base, manifest: { ...base.manifest, payload: { ...base.manifest.payload, safety: 'PASS' } } },
    { ...base, manifest: { ...base.manifest, publicKey: attackerKey } },
    { ...base, manifest: { ...base.manifest, payload: { ...base.manifest.payload, purpose: 'NPM_PROVENANCE' } } },
    { ...base, manifest: signDemoPublisherManifest(base.expectedIdentity, privateKey) },
  ]) assert.throws(() => verifyDemoPublisherManifest(input), /DEMO_PUBLISHER_/);
  const own = signDemoPublisherManifest(base.expectedIdentity, privateKey);
  assert.equal(verifyDemoPublisherManifest({ ...base, manifest: own, pinnedPublicKey: attackerKey }).verified, true);
  assert.throws(() => signDemoPublisherManifest({ ...base.expectedIdentity, privateKey: 'unsupported field' }, privateKey), /IDENTITY_INVALID/);
});

test('candidate input cannot configure publisher trust and OCI cannot silently ignore configured verification', async () => {
  const resolved = await resolveArtifact({ source: { type: 'local', path: fixture('1.0.0') }, demoPublisher: configuration('1.0.0') });
  try { assert.deepEqual(resolved.metadata.publisherEvidence, []); } finally { await resolved.cleanup(); }
  await assert.rejects(() => resolveArtifact({ source: { type: 'oci', locator: 'unused' } }, { demoPublisher: configuration('1.0.0') }),
    /DEMO_PUBLISHER_SOURCE_PROFILE_UNSUPPORTED/);
});
