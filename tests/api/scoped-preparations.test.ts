import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { hash, type ControlOptions } from "../../apps/api/src/control-plane.js";
import { preparedPolicy, scopedPreparedPolicy, validPolicy, policyVerdict } from "../../apps/api/src/control-policy.js";
import { checkedProvenanceCatalogue, checkedScopedConfig, loadScopedProvenance } from "../../apps/api/src/scoped-config.js";
import { claimPreparation, failPreparation, preparations } from "../../apps/api/src/preparation-store.js";
import { runPreparationWorkerOnce } from "../../apps/api/src/preparation-worker.js";
import { runControlWorkerOnce } from "../../apps/api/src/control-worker.js";
import { preparedTrust } from "../../apps/api/src/prepared-config.js";
import { exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";
// @ts-expect-error Shared strict binding helper.
import { createPreparedReleaseBinding } from "../../services/scanner/src/prepared-binding.mjs";
// @ts-expect-error Shared evidence helper.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared surface identity.
import { toolSurfaceHash } from "../../services/scanner/src/tool-surface.mjs";
// @ts-expect-error Shared descriptor identity.
import { hashPreparedRuntimeDescriptor } from "../../services/resolver/src/runtime-descriptor.mjs";
// @ts-expect-error Real bounded local snapshot; no candidate execution.
import { resolveArtifact } from "../../services/resolver/src/resolver.mjs";

const digest = `sha256:${"a".repeat(64)}`, tenant = "scoped-test", token = "synthetic-scoped-operator-token", foreign = "synthetic-scoped-other-token";
const declaration = { schemaVersion: "mcpshield.operator-code-artifact.v1", authority: "OPERATOR_LOCAL_CATALOG", contentClass: "CODE_ARTIFACT_NO_CUSTOMER_DATA", sourceArtifactDigest: digest };
const catalogue = (artifacts: any[] = [declaration]) => ({ schemaVersion: "mcpshield.scoped-provenance-catalogue.v1", artifacts });
const policy = scopedPreparedPolicy("LOCAL_CONTRACT_TEST"), policyHash = hash(policy);
const ai = { allowRemoteAi: true, disclosurePolicy: "SCOPED_PROVIDER_REVIEW_V1", evidenceMode: "LOCAL_CONTRACT_TEST", provider: "custom", url: "http://127.0.0.1:9", timeoutMs: 1000 };
async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), "mcpshield-scoped-api-")), filename = join(dir, "private-catalogue.json");
  const resolved = await resolveArtifact({ sourceType: "local", locator: fileURLToPath(new URL("../../demo/fixtures/mail-mcp-1.0.0", import.meta.url)) });
  const source = { ...exactReleaseIdentity(resolved), artifactDigest: resolved.artifactDigest, manifestDigest: resolved.manifestDigest, toolSurfaceHash: resolved.toolSurfaceHash,
    artifactDir: resolved.artifactDir, sourceType: "npm", legacyReleaseId: resolved.releaseId, status: "UNVERIFIED" };
  const localDeclaration = { ...declaration, sourceArtifactDigest: source.artifactDigest };
  await writeFile(filename, JSON.stringify(catalogue([localDeclaration])));
  const store = await ControlStore.open();
  const options: ControlOptions = { store, credentials: [{ tenantId: tenant, token, role: "operator" }, { tenantId: "foreign", token: foreign, role: "operator" }],
    artifactPath: join(dir, "artifacts"), evidencePath: join(dir, "evidence"), evidenceKey: "1".repeat(64),
    scannerOptions: { sandbox: "docker", allowRemoteAi: false }, preparedRuntime: { builderImageDigest: digest, platform: { os: "linux", architecture: "amd64" } },
    scopedPrepared: { provenancePaths: { [tenant]: filename }, ai } };
  options.inspectPreparedRuntime = async ({ descriptor }) => ({ ...preparedTrust(options.preparedRuntime!), finalImageDigest: descriptor.finalImageDigest,
    platform: descriptor.platform, entrypointDigest: descriptor.entrypoint.digest, closureDigest: digest,
    sourceDescriptorDigest: hashPreparedRuntimeDescriptor({ ...descriptor, stage: "PREFLIGHT", finalImageDigest: null, toolSurfaceHash: null }) });
  const app = await buildApp({ adminApiToken: "synthetic-legacy-admin", scannerApiToken: "synthetic-legacy-scanner", controlPlane: options });
  for (const id of [tenant, "foreign"]) await store.put(id, "release", source.releaseId, source);
  const request = (key: string, body: any = { policyHash }, bearer = token) => app.inject({ method: "POST", url: `/v1/releases/${source.releaseId}/prepare`, headers: { authorization: `Bearer ${bearer}`, "idempotency-key": key }, payload: body });
  return { dir, filename, app, store, options, request, source, declaration: localDeclaration, close: async () => { await app.close(); await resolved.cleanup(); await rm(dir, { recursive: true, force: true }); } };
}
function syntheticOutput(input: any, cleanup: () => Promise<void>) {
  const tools = [{ name: "list_messages", inputSchema: { type: "object", properties: {}, additionalProperties: false } }];
  const sourceDigest = input.preparation?.sourceTreeDigest ?? input.descriptor.sourceTreeDigest;
  const descriptor = { schemaVersion: "mcpshield.prepared-runtime.v1", stage: "CLOSURE_PREPARED", profile: "npm-closure-v1", sourceDigest, sourceTreeDigest: sourceDigest,
    lockDigest: digest, lockOrigin: "SUPPLIED", builderImageDigest: digest, platform: input.preparation?.platform ?? input.descriptor.platform,
    finalImageDigest: digest, toolSurfaceHash: toolSurfaceHash(tools), entrypoint: { path: "server.js", digest }, argv: ["/usr/local/bin/node", "/app/server.js"],
    policy: { acquisitionNetwork: "REGISTRY_ONLY_SEPARATE", installNetwork: "NONE", installScripts: "DISABLED", executionNetwork: "INTERNAL_SYNTHETIC_PROXY", user: "NON_ROOT", rootFilesystem: "READ_ONLY" } };
  const binding = createPreparedReleaseBinding({ sourceReleaseId: input.sourceReleaseId, descriptor, executionPolicy: input.scopedReview.executionPolicy });
  const result = { schemaVersion: "1.0.0", scanId: input.scanId, releaseId: input.releaseId, artifactDigest: binding.artifactDigest,
    toolSurfaceHash: binding.toolSurfaceHash, scanStatus: "INCONCLUSIVE", findings: [], evidenceHash: `0x${"1".repeat(64)}`, source: "MOCK" };
  return { binding, result, analysis: { profile: policy.profile, verdict: "ABSTAIN", issues: ["SYNTHETIC_NO_DOCKER"] }, cleanup,
    runtimeTag: `mcpshield-runtime-${randomUUID()}:local`, bundle: createEvidenceBundle({ "report.json": result, "prepared/binding.json": binding,
      "runtime/descriptor.json": descriptor, "runtime/execution-policy.json": binding.executionPolicy, "runtime/tools.json": tools }) };
}

test("scoped catalogue is exact bounded digest authority; empty/replaced files revoke without exposing paths", async () => {
  assert.deepEqual(checkedProvenanceCatalogue(catalogue()), [declaration]); assert.deepEqual(checkedProvenanceCatalogue(catalogue([])), []);
  for (const value of [{ ...catalogue(), extra: true }, catalogue([declaration, declaration]), catalogue(Array(129).fill(declaration)), catalogue([{ ...declaration, allowRemoteAi: true }])]) assert.throws(() => checkedProvenanceCatalogue(value));
  assert.throws(() => checkedScopedConfig({ provenancePaths: { [tenant]: "relative" }, ai }), /CONFIG_INVALID/);
  const dir = await mkdtemp(join(tmpdir(), "mcpshield-scoped-catalogue-")), path = join(dir, "private.json");
  try {
    await writeFile(path, JSON.stringify(catalogue())); assert.deepEqual(await loadScopedProvenance(path, digest), declaration);
    for (const content of [JSON.stringify(catalogue([])), "{}", "bad-json", " ".repeat(512 * 1024 + 1)]) {
      await writeFile(path, content); await assert.rejects(loadScopedProvenance(path, digest), (error: any) => error.message === "SCOPED_OPERATOR_PROVENANCE_REQUIRED");
    }
    await assert.rejects(loadScopedProvenance(join(dir, "missing-private-file"), digest), (error: any) => error.message === "SCOPED_OPERATOR_PROVENANCE_REQUIRED");
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("Node v2 policies preserve v1 hashes and require exact semantic mode without OCI/baseline fallback", () => {
  assert.equal(preparedPolicy.version, "1.0.0"); assert.equal(validPolicy(policy), true); assert.notEqual(hash(preparedPolicy), policyHash);
  assert.notEqual(hash(scopedPreparedPolicy("PROVIDER_EXECUTION")), policyHash);
  for (const edit of [{ version: "1.0.0" }, { profile: "restricted-oci-offline-v2" }, { semantic: undefined }, { semantic: { ...policy.semantic, extra: true } }, { requireCritic: false }]) assert.equal(validPolicy({ ...policy, ...edit }), false);
  assert.equal(policyVerdict({ files: {} }, {}, policy), "ABSTAIN");
});

test("Node v2 scan/appeal checks exact mode inside the transaction without consuming a rejected appeal slot", async () => {
  const f = await fixture();
  const payload = { releaseId: f.source.releaseId, policyHash }, headers = { authorization: `Bearer ${token}`, "idempotency-key": "mode-check" };
  const target = { ...f.source, runtimeProfile: policy.profile, semanticEvidenceMode: "LOCAL_CONTRACT_TEST", status: "REVOKED", policyHash: hash(preparedPolicy) };
  try {
    await f.store.put(tenant, "release", target.releaseId, target, true);
    const opened = await f.app.inject({ method: "POST", url: `/v1/releases/${target.releaseId}/appeals`, headers, payload: { reason: "Synthetic scoped mode regression" } });
    assert.equal(opened.statusCode, 201, opened.body);
    const appealId = opened.json().appeal.appealId;
    const providerHash = hash(scopedPreparedPolicy("PROVIDER_EXECUTION"));
    for (const body of [{ ...payload, policyHash: providerHash }, { ...payload, policyHash: providerHash, appealId }]) {
      const denied = await f.app.inject({ method: "POST", url: "/v1/scans", headers, payload: body });
      assert.equal(denied.statusCode, 409); assert.equal(denied.json().error.code, "SCAN_SEMANTIC_MODE_MISMATCH");
    }
    // Simulate a projection change after the route's first read. The queue transaction must reread authority.
    for (const semanticEvidenceMode of [undefined, "INVALID", "PROVIDER_EXECUTION"]) {
      await f.store.put(tenant, "release", target.releaseId, { ...target, semanticEvidenceMode }, true);
      for (const input of [{ ...payload, artifactDigest: target.artifactDigest }, { ...payload, artifactDigest: target.artifactDigest, appealId }]) {
        await assert.rejects(f.store.enqueueConstrained(tenant, input, "mode-check", hash(input), randomUUID(), target, policy),
          (error: any) => error.statusCode === 409 && error.message === "SCAN_SEMANTIC_MODE_MISMATCH");
      }
    }
    assert.equal((await f.store.get(tenant, "appeal", appealId))?.rescan, null);
    assert.equal((await f.store.scanUsage(tenant)).queued, 0);
    assert.equal((await f.store.query("SELECT COUNT(*) AS count FROM cp_scan_request_keys"))[0].count, 0);
    await f.store.put(tenant, "release", target.releaseId, target, true);
    const accepted = await f.app.inject({ method: "POST", url: "/v1/scans", headers, payload: { ...payload, appealId } });
    assert.equal(accepted.statusCode, 202, accepted.body);
    assert.equal((await f.store.get(tenant, "appeal", appealId))?.rescan.scanId, accepted.json().scan.scanId);
    const retry = await f.app.inject({ method: "POST", url: "/v1/scans", headers, payload: { ...payload, appealId } });
    assert.equal(retry.statusCode, 202); assert.equal(retry.json().scan.scanId, accepted.json().scan.scanId);
  } finally { await f.close(); }
});

test("scoped prepare is server-only, tenant-local, frozen on retry and revoked before any scanner request", async () => {
  const f = await fixture(); let calls = 0;
  try {
    f.options.prepareRuntime = async () => { calls++; throw Error("UNEXPECTED_EXECUTION"); };
    const lower = { ...policy, maxArtifactBytes: 1024 }, lowerHash = hash(lower);
    await f.store.put(tenant, "policy", lowerHash, { document: lower });
    const overBudget = await f.request("over-budget", { policyHash: lowerHash });
    assert.equal(overBudget.json().error.code, "SCOPED_SOURCE_BUDGET_EXCEEDED"); assert.equal(calls, 0);
    for (const field of ["sourceProvenance", "scopedReview", "executionPolicy", "ai", "aiToken", "provenancePath"]) assert.equal((await f.request(field, { policyHash, [field]: declaration })).statusCode, 400);
    assert.equal((await f.request("foreign", undefined, foreign)).statusCode, 400);
    const accepted = await f.request("same"); assert.equal(accepted.statusCode, 202, accepted.body);
    assert.equal((await f.request("same")).json().preparation.preparationId, accepted.json().preparation.preparationId);
    assert.doesNotMatch(accepted.body, /private-catalogue|sourceProvenance|127\.0\.0\.1|PRIVATE_SOURCE|aiConfigHash/);
    const job = (await claimPreparation(f.store, "worker"))!;
    assert.doesNotMatch(JSON.stringify(job.request), /127\.0\.0\.1|private-catalogue/);
    await failPreparation(f.store, job, "worker", "WORKER_LOST", true);
    await f.store.query("UPDATE cp_preparations SET state='DEAD_LETTER' WHERE preparation_id=?", [job.preparationId]);
    f.options.scopedPrepared!.ai = { ...ai, timeoutMs: 2000 };
    assert.equal((await f.app.inject({ method: "POST", url: `/v1/preparations/${job.preparationId}/retry`, headers: { authorization: `Bearer ${token}` }, payload: {} })).statusCode, 409);
    f.options.scopedPrepared!.ai = ai;
    assert.equal((await f.app.inject({ method: "POST", url: `/v1/preparations/${job.preparationId}/retry`, headers: { authorization: `Bearer ${token}` }, payload: {} })).statusCode, 200);
    await writeFile(f.filename, JSON.stringify(catalogue([])));
    await runPreparationWorkerOnce(f.store, f.options);
    assert.equal(calls, 0); assert.equal((await preparations(f.store, tenant, job.preparationId))[0].status, "DEAD_LETTER");
    assert.equal((await f.request("after-revoke")).statusCode, 400);
  } finally { await f.close(); }
});

test("Node v2 prepare/rescan dispatch preserve provenance labels, final revocation rolls back, and MOCK can never PASS", async () => {
  const f = await fixture(); let calls = 0, cleaned = 0;
  try {
    f.options.prepareRuntime = async input => { calls++; assert.equal(input.scopedReview.executionPolicy.profile, policy.profile); assert.deepEqual(input.scopedReview.sourceProvenance, f.declaration);
      assert.equal(input.ai.disclosurePolicy, "SCOPED_PROVIDER_REVIEW_V1"); return syntheticOutput(input, async () => { cleaned++; }); };
    const accepted = await f.request("first"); assert.equal(accepted.statusCode, 202, accepted.body);
    await runPreparationWorkerOnce(f.store, f.options);
    const completed = (await preparations(f.store, tenant, accepted.json().preparation.preparationId))[0];
    assert.equal(completed.status, "COMPLETED", JSON.stringify(completed.lastError)); assert.equal(completed.result?.verdict, "ABSTAIN");
    assert.equal(completed.result?.semanticEvidenceMode, "LOCAL_CONTRACT_TEST");
    const releaseId = completed.result!.releaseId, release = await f.store.get(tenant, "release", releaseId);
    assert.equal(release?.providerQuality, "PROVIDER_QUALITY_NOT_MEASURED"); assert.equal(calls, 1); assert.equal(cleaned, 0);
    await f.store.put(tenant, "release", releaseId, { ...release, chainUnavailable: true, chain: { blockNumber: 7 } }, true);
    const projected = (await f.app.inject({ url: `/v1/releases/${releaseId}`, headers: { authorization: `Bearer ${token}` } })).json().release;
    assert.equal(projected.chainUnavailable, true); assert.equal(projected.chain.blockNumber, 7);
    f.options.scanPreparedRuntime = async input => { calls++; return syntheticOutput(input, async () => {}); };
    const scan = await f.app.inject({ method: "POST", url: "/v1/scans", headers: { authorization: `Bearer ${token}`, "idempotency-key": "rescan" }, payload: { releaseId, policyHash } });
    assert.equal(scan.statusCode, 202); await runControlWorkerOnce(f.store, f.options);
    const stored = await f.store.scan(tenant, scan.json().scan.scanId); assert.equal(stored?.status, "COMPLETED"); assert.equal(stored?.result?.verdict, "ABSTAIN"); assert.equal(calls, 2);
    for (const url of [`/v1/scans/${stored!.scanId}`, `/v1/releases/${releaseId}`, `/v1/preparations/${completed.preparationId}`]) {
      const read = await f.app.inject({ url, headers: { authorization: `Bearer ${token}` } }); assert.equal(read.statusCode, 200);
      assert.doesNotMatch(read.body, /sourceProvenance|scopedConfigHash|preparedRuntimeTrust|provenancePath|private-catalogue|127\.0\.0\.1/);
      assert.match(read.body, /LOCAL_CONTRACT_TEST/);
    }
    f.options.prepareRuntime = async input => { const output = syntheticOutput(input, async () => { cleaned++; }); await writeFile(f.filename, JSON.stringify(catalogue([]))); return output; };
    const second = await f.request("second"); assert.equal(second.statusCode, 202);
    await runPreparationWorkerOnce(f.store, f.options);
    assert.equal((await preparations(f.store, tenant, second.json().preparation.preparationId))[0].status, "DEAD_LETTER"); assert.equal(cleaned, 1);
    assert.equal((await f.store.query("SELECT COUNT(*) AS count FROM cp_scans WHERE tenant_id=?", [tenant]))[0].count, 2);
  } finally { await f.close(); }
});
