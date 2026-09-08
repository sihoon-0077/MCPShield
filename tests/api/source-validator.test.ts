import assert from "node:assert/strict";
import { test } from "node:test";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkedValidatorSources, loadValidatorSources, checkedSourceIdentity, compareSourceScans, independentlyScanSource } from "../../apps/validator/src/source-verification.js";
import { defaultPolicy } from "../../apps/api/src/control-policy.js";
import { exactReleaseIdentity, bytes32 } from "../../packages/contracts-sdk/src/v2.js";
// @ts-expect-error Shared resolver is ESM JavaScript.
import { resolveArtifact } from "../../services/resolver/src/resolver.mjs";
// @ts-expect-error Shared bundle helper is ESM JavaScript.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared actual scanner is ESM JavaScript.
import { scanResolvedArtifact } from "../../services/scanner/src/scanner.mjs";

const fixturePath = (version = "1.0.0") => fileURLToPath(new URL(`../../demo/fixtures/mail-mcp-${version}`, import.meta.url));
const catalog = (releaseId: string, locator = fixturePath()) => ({ schemaVersion: "mcpshield.validator-sources.v1" as const, sources: [{ releaseId, sourceType: "local" as const, locator }] });
async function fixture() {
  const source = await resolveArtifact({ sourceType: "local", locator: fixturePath() });
  const exact = exactReleaseIdentity(source), identity = { ...exact, exists: true, artifactDigest: bytes32(source.artifactDigest), manifestDigest: bytes32(source.manifestDigest), toolSurfaceDigest: source.toolSurfaceHash };
  const sourceIdentity = checkedSourceIdentity(source, identity, exact.releaseId);
  // Synthetic reports deliberately exercise reconstruction; they do not prove Docker execution.
  const result = { schemaVersion: "1.0.0", scanId: randomUUID(), releaseId: source.releaseId, artifactDigest: source.artifactDigest,
    toolSurfaceHash: source.toolSurfaceHash, scanStatus: "PASSED", findings: [], evidenceHash: `0x${"a".repeat(64)}`, source: "LIVE" };
  const documents = { "report.json": { ...result, scope: "STATIC_AI_SANDBOX" }, "static/findings.json": [], "static/package-diff.json": { hasBaseline: false },
    "sandbox/events.json": { mode: "DOCKER", complete: true }, "sandbox/mcp.json": { complete: true },
    "semantic/model-output.json": { findings: [], execution: { status: "LOCAL_FALLBACK" } } };
  const second = { ...result, scanId: randomUUID() };
  return { source, identity, exact, sourceIdentity, result, documents, bundle: createEvidenceBundle(documents),
    independent: { result: second, bundle: createEvidenceBundle({ ...documents, "report.json": { ...second, scope: "STATIC_AI_SANDBOX" } }), sourceIdentity, baselineReleaseId: null } };
}
test("validator source catalog is exact, bounded, local-only configuration with immutable npm/OCI references", async () => {
  const releaseId = `0x${"1".repeat(64)}`, config = catalog(releaseId), dir = await mkdtemp(join(tmpdir(), "mcpshield-source-catalog-"));
  try {
    assert.deepEqual(checkedValidatorSources(config), config);
    const filename = join(dir, "sources.json"); await writeFile(filename, JSON.stringify(config), { mode: 0o600 });
    assert.deepEqual(await loadValidatorSources(filename), config);
    for (const bad of [{ ...config, token: "do-not-accept" }, { ...config, sources: [] }, { ...config, sources: Array(129).fill(config.sources[0]) },
      { ...config, sources: [config.sources[0], config.sources[0]] }, { ...config, sources: [{ ...config.sources[0], providerUrl: "http://127.0.0.1" }] },
      { ...config, sources: [{ ...config.sources[0], locator: "relative/server" }] },
      { ...config, sources: [{ ...config.sources[0], sourceType: "npm", locator: "mail-mcp@latest" }] },
      { ...config, sources: [{ ...config.sources[0], sourceType: "tarball", locator: "http://127.0.0.1/internal" }] },
      { ...config, sources: [{ ...config.sources[0], sourceType: "oci", locator: "ghcr.io/team/image:latest" }] }]) assert.throws(() => checkedValidatorSources(bad));
    assert.doesNotThrow(() => checkedValidatorSources({ ...config, sources: [{ ...config.sources[0], sourceType: "npm", locator: "@team/tool@1.0.0" }] }));
    await writeFile(filename, " ".repeat(512 * 1024 + 1)); await assert.rejects(loadValidatorSources(filename), /FILE_INVALID/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
test("source verification independently binds all chain identity fields and rejects fabricated completeness, baseline loss and reused scans", async () => {
  const f = await fixture();
  try {
    assert.equal(compareSourceScans(f, f.independent, defaultPolicy, f.identity, f.exact.releaseId).semanticExecution, "LOCAL_STRUCTURED_FALLBACK_V1");
    for (const field of ["artifactDigest", "manifestDigest", "toolSurfaceDigest", "toolId"]) assert.throws(() => checkedSourceIdentity(f.source, { ...f.identity, [field]: `0x${"e".repeat(64)}` }, f.exact.releaseId), /CHAIN_MISMATCH/);
    assert.throws(() => compareSourceScans(f, { ...f.independent, result: f.result }, defaultPolicy, f.identity, f.exact.releaseId), /IDENTITY_MISMATCH/);
    assert.throws(() => compareSourceScans(f, f.independent, defaultPolicy, f.identity, f.exact.releaseId, `0x${"e".repeat(64)}`), /IDENTITY_MISMATCH/);
    assert.throws(() => compareSourceScans({ ...f, bundle: createEvidenceBundle({ ...f.documents, "static/package-diff.json": { hasBaseline: true } }) },
      f.independent, defaultPolicy, f.identity, f.exact.releaseId), /BASELINE_MISMATCH/);
    const documents = { ...f.documents, "report.json": { ...f.independent.result, scope: "STATIC_AI_SANDBOX" }, "sandbox/events.json": { mode: "NOT_EXECUTED", complete: false } };
    assert.throws(() => compareSourceScans(f, { ...f.independent, bundle: createEvidenceBundle(documents) }, defaultPolicy, f.identity, f.exact.releaseId), /DID_NOT_CONFIRM/);
    await assert.rejects(independentlyScanSource(f, defaultPolicy, f.identity, f.exact.releaseId, catalog(`0x${"e".repeat(64)}`)), /SOURCE_NOT_CONFIGURED/);
    await assert.rejects(independentlyScanSource(f, defaultPolicy, f.identity, f.exact.releaseId, catalog(f.exact.releaseId),
      { releaseId: `0x${"e".repeat(64)}`, identity: f.identity }), /SOURCE_NOT_CONFIGURED/);
    await assert.rejects(independentlyScanSource(f, defaultPolicy, f.identity, f.exact.releaseId, {
      schemaVersion: "mcpshield.validator-sources.v1", sources: [{ releaseId: f.exact.releaseId, sourceType: "oci", locator: `ghcr.io/team/image@sha256:${"a".repeat(64)}` }] }), /OCI_RUNTIME_UNOBSERVED/);
    // Actual independent reacquisition of different immutable bytes is rejected before any candidate execution.
    await assert.rejects(independentlyScanSource(f, defaultPolicy, f.identity, f.exact.releaseId, catalog(f.exact.releaseId, fixturePath("1.0.1"))), /CHAIN_MISMATCH/);
  } finally { await f.source.cleanup(); }
});
test("source validator re-acquires and executes its own Docker scan, including bound baseline (actual Docker, no remote AI)", {
  skip: process.env.MCPSHIELD_DOCKER_TESTS !== "1", timeout: 120000,
}, async () => {
  const safe = await resolveArtifact({ sourceType: "local", locator: fixturePath() });
  const bad = await resolveArtifact({ sourceType: "local", locator: fixturePath("1.0.1") });
  try {
    const identity = (source: any) => ({ ...exactReleaseIdentity(source), exists: true, artifactDigest: bytes32(source.artifactDigest), manifestDigest: bytes32(source.manifestDigest), toolSurfaceDigest: source.toolSurfaceHash });
    const safeIdentity = identity(safe), badIdentity = identity(bad);
    const sources = { schemaVersion: "mcpshield.validator-sources.v1" as const, sources: [safe, bad].map((source) => ({
      releaseId: exactReleaseIdentity(source).releaseId, sourceType: "local" as const, locator: fixturePath(source.version) })) };
    const original = await scanResolvedArtifact({ artifactDir: bad.artifactDir, baselineDir: safe.artifactDir, sandbox: "docker", sandboxTimeoutMs: 15000, logger: () => {} });
    const second = await independentlyScanSource(original, defaultPolicy, badIdentity, badIdentity.releaseId, sources, { releaseId: safeIdentity.releaseId, identity: safeIdentity });
    assert.equal(second.comparison.verdict, "FAIL"); assert.notEqual(second.comparison.originalReportRoot, second.comparison.independentReportRoot);
    assert.equal(second.comparison.verificationProfile, "SOURCE_DOCKER_V1"); assert.equal(second.comparison.semanticExecution, "LOCAL_STRUCTURED_FALLBACK_V1");
  } finally { await safe.cleanup(); await bad.cleanup(); }
});
