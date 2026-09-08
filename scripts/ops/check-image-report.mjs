import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const requiredPackages = ['fastify', 'next', '@modelcontextprotocol/server', '@aws-sdk/client-s3'];
export function checkImageReport(report, expectedImageId, revision) {
  assert.match(expectedImageId, /^sha256:[a-f0-9]{64}$/);
  assert.equal(report.ArtifactType, 'container_image', 'Missing container image scan');
  assert.equal(report.Metadata?.ImageID, expectedImageId, 'Scanned image does not match the build');
  assert.equal(report.Metadata?.ImageConfig?.config?.Labels?.['org.opencontainers.image.revision'], revision, 'Wrong source revision');
  assert.equal(report.Metadata?.OS?.Family, 'alpine', 'Missing OS identification');
  assert.ok(report.Results?.some(r => r.Class === 'os-pkgs' && r.Type === 'alpine' && r.Packages?.length), 'Missing OS package coverage');
  const packages = report.Results?.filter(r => r.Class === 'lang-pkgs' && r.Type === 'node-pkg').flatMap(r => r.Packages ?? []) ?? [];
  for (const name of requiredPackages) assert.ok(packages.some(p => p.Name === name && /^app\/(?:.*\/)?node_modules\//.test(p.FilePath ?? '')), `Missing application dependency coverage: ${name}`);
  const severe = report.Results.flatMap(r => r.Vulnerabilities ?? []).filter(v => ['HIGH', 'CRITICAL'].includes(v.Severity));
  assert.equal(severe.length, 0, `Image HIGH/CRITICAL vulnerability gate failed: ${severe.length}`);
  return { imageId: expectedImageId, revision, applicationPackages: packages.length, highCritical: 0 };
}
export function checkImageSbom(sbom) {
  assert.equal(sbom.bomFormat, 'CycloneDX');
  assert.ok(Array.isArray(sbom.components) && sbom.components.length, 'Missing SBOM components');
  for (const name of requiredPackages) {
    assert.ok(sbom.components.some(c => {
      if (typeof c.purl !== 'string' || !c.purl.startsWith('pkg:npm/')) return false;
      try { return decodeURIComponent(c.purl).startsWith(`pkg:npm/${name}@`); } catch { return false; }
    }), `Missing SBOM application package: ${name}`);
  }
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const [scanPath, imageIdPath, revision, sbomPath] = process.argv.slice(2);
  assert.match(revision ?? '', /^[a-f0-9]{40}$/);
  const result = checkImageReport(JSON.parse(readFileSync(scanPath, 'utf8')), readFileSync(imageIdPath, 'utf8').trim(), revision);
  if (sbomPath) checkImageSbom(JSON.parse(readFileSync(sbomPath, 'utf8')));
  console.log(JSON.stringify({ ...result, sbomChecked: Boolean(sbomPath), licenseInventoryIsLegalApproval: false }));
}
