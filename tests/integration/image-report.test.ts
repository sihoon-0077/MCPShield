import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
// @ts-expect-error Shared exact toolchain identity is ESM JavaScript.
import { TOOLCHAIN_PATCHES, TOOLCHAIN_PATCH_SET } from '../../services/resolver/src/closure-files.mjs';
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
test('runtime builder scans require the trusted global toolchain rather than release-app packages', () => {
  const npmPackage = { Name: 'npm', Version: '12.0.2', FilePath: 'usr/local/lib/node_modules/npm/package.json' };
  const builder = { ...report(), Results: [report().Results[0], { Class: 'lang-pkgs', Type: 'node-pkg', Packages: [
    npmPackage,
    { Name: 'tar', Version: '7.5.22', FilePath: 'usr/local/lib/node_modules/npm/node_modules/tar/package.json' },
  ] }] };
  assert.equal(checkImageReport(builder, imageId, revision, 'runtime-builder').highCritical, 0);
  for (const Severity of ['HIGH', 'CRITICAL']) assert.throws(() => checkImageReport({ ...builder,
    Results: [...builder.Results, { Vulnerabilities: [{ Severity }] }] }, imageId, revision, 'runtime-builder'), /vulnerability gate/);
  assert.throws(() => checkImageReport(builder, imageId, revision), /application dependency coverage/);
  npmPackage.Version = '0.0.0';
  assert.throws(() => checkImageReport(builder, imageId, revision, 'runtime-builder'), /Wrong trusted npm/);
});

test('builder acquisition, installed-version checks and runtime evidence use the same exact patch set', () => {
  const dockerfile = readFileSync(new URL('../../services/resolver/Dockerfile.builder', import.meta.url), 'utf8');
  const archives = JSON.parse(dockerfile.match(/const patches=(\[.*?\]);/)![1].replaceAll("'", '"')) as string[][];
  const versions = Object.entries(TOOLCHAIN_PATCHES);
  assert.deepEqual(archives.map(([name, version]) => [name, version]), versions);
  for (const [, , integrity] of archives) assert.match(integrity, /^[A-Za-z0-9+/]{86}==$/);
  assert.deepEqual(JSON.parse(dockerfile.match(/of (\[\[.*?\]\])\)/)![1].replaceAll("'", '"')), versions);
  assert.equal(dockerfile.match(/for pkg in ([^;]+); do/)![1], Object.keys(TOOLCHAIN_PATCHES).join(' '));
  assert.equal(dockerfile.match(/LABEL io\.mcpshield\.npm-patches="([^"]+)"/)![1], TOOLCHAIN_PATCH_SET);
  assert.match(dockerfile, /COPY[^\n]*closure-files\.mjs \/trusted\//);
});
