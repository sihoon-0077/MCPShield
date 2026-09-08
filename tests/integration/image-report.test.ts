import assert from 'node:assert/strict';
import { test } from 'node:test';
// @ts-expect-error The CI evidence gate is native ESM and validates untrusted JSON at runtime.
import { checkImageReport, checkImageSbom } from '../../scripts/ops/check-image-report.mjs';
const imageId = `sha256:${'a'.repeat(64)}`, revision = 'b'.repeat(40);
const names = ['fastify', 'next', '@modelcontextprotocol/server', '@aws-sdk/client-s3'];
const report = () => ({ ArtifactType: 'container_image', Metadata: { ImageID: imageId, OS: { Family: 'alpine' }, ImageConfig: { config: { Labels: { 'org.opencontainers.image.revision': revision } } } }, Results: [
  { Class: 'os-pkgs', Type: 'alpine', Packages: [{ Name: 'libcrypto3' }] },
  { Class: 'lang-pkgs', Type: 'node-pkg', Packages: names.map(Name => ({ Name, FilePath: `app/node_modules/${Name}/package.json` })) },
] });
test('image evidence requires actual OS and application coverage bound to the built image', () => {
  assert.equal(checkImageReport(report(), imageId, revision).highCritical, 0);
  const changed = report(); changed.Metadata.ImageID = `sha256:${'c'.repeat(64)}`;
  assert.throws(() => checkImageReport(changed, imageId, revision), /does not match/);
  assert.throws(() => checkImageReport(report(), imageId, 'd'.repeat(40)), /Wrong source/);
  assert.throws(() => checkImageReport({ ...report(), Results: [{ Class: 'license', Type: 'license-file', Packages: [{}] }] }, imageId, revision), /OS package coverage/);
  const globalOnly = report(); globalOnly.Results[1].Packages = names.map(Name => ({ Name, FilePath: `usr/local/lib/node_modules/npm/node_modules/${Name}/package.json` }));
  assert.throws(() => checkImageReport(globalOnly, imageId, revision), /application dependency coverage/);
  assert.throws(() => checkImageReport({ ...report(), Results: [...report().Results, { Vulnerabilities: [{ Severity: 'CRITICAL' }] }] }, imageId, revision), /vulnerability gate/);
});
test('CycloneDX evidence must contain the actual application dependencies', () => {
  const components = names.map(name => ({ purl: `pkg:npm/${encodeURIComponent(name)}@1.0.0` }));
  checkImageSbom({ bomFormat: 'CycloneDX', components });
  assert.throws(() => checkImageSbom({ bomFormat: 'CycloneDX', components: components.slice(1) }), /Missing SBOM/);
  assert.throws(() => checkImageSbom({ bomFormat: 'CycloneDX', components: [] }), /Missing SBOM/);
});
