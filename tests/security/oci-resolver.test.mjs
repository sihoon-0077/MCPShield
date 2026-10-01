import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { inspectOciImage, parseOciLocator } from '../../services/resolver/src/oci.mjs';
import { resolveArtifact } from '../../services/resolver/src/resolver.mjs';
import { scanResolvedArtifact, redactEvidenceDocument } from '../../services/scanner/src/scanner.mjs';
import { canonicalJson } from '../../services/scanner/src/evidence.mjs';

test('OCI resolves exact platform, verifies every blob, reports root and never claims a discovered surface', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'mcpshield-oci-test-'));
  const blobs = new Map();
  const blob = (content, mediaType) => {
    const bytes = Buffer.from(content);
    const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
    blobs.set(digest, bytes);
    return { digest, size: bytes.length, mediaType };
  };
  try {
    const layer = blob('synthetic opaque layer: not executable', 'application/vnd.oci.image.layer.v1.tar');
    const config = blob(JSON.stringify({ os: 'linux', architecture: 'amd64', config: { User: '0', Env: ['DEMO_TOKEN=synthetic-private-marker'], Cmd: ['demo'] } }), 'application/vnd.oci.image.config.v1+json');
    const manifest = blob(JSON.stringify({ schemaVersion: 2, config, layers: [layer] }), 'application/vnd.oci.image.manifest.v1+json');
    const index = { schemaVersion: 2, manifests: [{ ...manifest, platform: { os: 'linux', architecture: 'amd64' } }] };
    const image = await inspectOciImage({ index, readBlob: async ({ digest }) => blobs.get(digest) });
    assert.equal(image.imageDigest, manifest.digest);
    assert.equal(image.runtime.rootUser, true);
    assert.deepEqual(image.runtime.environmentNames, ['DEMO_TOKEN']);
    assert.equal(JSON.stringify(image.runtime).includes('synthetic-private-marker'), false);
    await assert.rejects(() => inspectOciImage({ index, readBlob: async () => Buffer.from('tampered') }), /INTEGRITY/);
    await assert.rejects(() => inspectOciImage({ index, readBlob: async ({ digest }) => blobs.get(digest), platform: { os: 'linux', architecture: 'arm64' } }), /platform/);
    await assert.rejects(() => inspectOciImage({ index: { ...index, manifests: [...index.manifests, ...index.manifests] },
      readBlob: async ({ digest }) => blobs.get(digest) }), /platform.*ambiguous/);
    await assert.rejects(() => inspectOciImage({ index, readBlob: async ({ digest }) => blobs.get(digest),
      platform: { os: 'linux', architecture: 'amd64', variant: 'unselected' } }), /PLATFORM_UNSUPPORTED/);
    await mkdir(join(workspace, 'blobs/sha256'), { recursive: true });
    for (const [digest, bytes] of blobs) await writeFile(join(workspace, 'blobs/sha256', digest.slice(7)), bytes);
    await writeFile(join(workspace, 'oci-layout'), JSON.stringify({ imageLayoutVersion: '1.0.0' }));
    await writeFile(join(workspace, 'index.json'), JSON.stringify(index));
    const resolved = await resolveArtifact({ source: { type: 'oci-layout', path: workspace } });
    try {
      assert.equal(resolved.metadata.imageDigest, manifest.digest);
      assert.equal(resolved.metadata.allLayerDigestsVerified, true);
      assert.equal(resolved.metadata.runtimePreparation.ready, false);
      assert.equal(resolved.metadata.runtimePreparation.descriptor.sourceDigest, manifest.digest);
      assert.ok(resolved.metadata.runtimePreparation.issues.includes('RUNTIME_OCI_NON_ROOT_REQUIRED'));
      const scanned = await scanResolvedArtifact({ artifactDir: resolved.artifactDir, logger: () => {} });
      assert.equal(scanned.result.scanStatus, 'INCONCLUSIVE');
      assert.equal(JSON.stringify(scanned.bundle).includes('synthetic-private-marker'), false);
    } finally { await resolved.cleanup(); }
  } finally { await rm(workspace, { recursive: true, force: true }); }
});

test('OCI registry input and evidence Unicode/redaction reject trust-boundary evasions', () => {
  assert.equal(parseOciLocator('ghcr.io/example/tool:1.0.0').reference, '1.0.0');
  assert.throws(() => parseOciLocator('localhost/../../metadata:latest'), /locator/);
  assert.throws(() => canonicalJson({ key: '\ud800' }), /surrogate/);
  assert.throws(() => canonicalJson({ '\udfff': 1 }), /surrogate/);
  const token = 'ghp_' + 'Q'.repeat(32);
  const sanitized = redactEvidenceDocument({ sbom: [{ version: `https://user:${token}@example.test/pkg?token=${token}` }], nested: { api_key: 'not-public', tokenHash: 'sha256:0123' } });
  assert.equal(JSON.stringify(sanitized).includes(token), false);
  assert.equal(sanitized.nested.api_key, '[REDACTED]');
  assert.equal(sanitized.nested.tokenHash, 'sha256:0123');
});
