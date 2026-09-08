import assert from "node:assert/strict";
import { test } from "node:test";
import { resolve, join } from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { hash, type ControlOptions } from "../../apps/api/src/control-plane.js";
import { assertRuntimeBudget, defaultPolicy, ociPolicy, policyVerdict, preparedPolicy, validPolicy } from "../../apps/api/src/control-policy.js";
import { checkedOciConfig, checkedOciTrust, ociTrust, type OciConfig } from "../../apps/api/src/oci-config.js";
import { controlConfig } from "../../apps/api/src/control-config.js";
import { claimPreparation, failPreparation, preparations } from "../../apps/api/src/preparation-store.js";
import { checkedOciEvidence, checkedPreparedEvidence } from "../../apps/api/src/prepared-evidence.js";
import { exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";
import { runPreparationWorkerOnce } from "../../apps/api/src/preparation-worker.js";
import { runControlWorkerOnce } from "../../apps/api/src/control-worker.js";
// @ts-expect-error Shared pure OCI identity helpers; these tests never execute a container.
import { ociExecutionPolicy, createOciReleaseBinding } from "../../services/scanner/src/oci-binding.mjs";
// @ts-expect-error Shared fixed OCI descriptor contract.
import { OCI_SOURCE_BUDGET_PROFILE, OCI_OBSERVATION_POLICY } from "../../services/resolver/src/oci-runtime-descriptor.mjs";
// @ts-expect-error Shared encrypted-evidence input format.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared complete tool metadata commitment.
import { toolSurfaceHash } from "../../services/scanner/src/tool-surface.mjs";

const digest = `sha256:${"a".repeat(64)}`, tenant = "oci-contract", token = "oci-contract-operator-token", reader = "oci-contract-reader-token", other = "oci-other-operator-token";
const config: OciConfig = { baseImageDigest: digest, baseCatalogueDigest: digest, trivyImageDigest: digest, databaseDigest: digest,
  databaseDir: resolve("unused-private-oci-db"), sinkImageDigest: digest, platform: { os: "linux", architecture: "amd64" } };
const sourceIdentity = { ...exactReleaseIdentity({ toolId: "oci:synthetic-contract", artifactDigest: digest, manifestDigest: digest, toolSurfaceHash: toolSurfaceHash([]) }),
  artifactDigest: digest, manifestDigest: digest, toolSurfaceHash: toolSurfaceHash([]) };
const source = { ...sourceIdentity, sourceType: "oci", artifactDir: "unused-private-layout", legacyReleaseId: "oci-contract@0.0.0", status: "UNVERIFIED" };

test("OCI policy fixes test-only semantic scope and separates 100MiB source from 512MiB expanded bytes", () => {
  assert.equal(validPolicy(ociPolicy), true); assert.equal(validPolicy(preparedPolicy), true); assert.equal(validPolicy(defaultPolicy), true);
  assert.notEqual(hash(ociPolicy), hash(preparedPolicy));
  for (const edit of [{ semanticEvidenceMode: undefined }, { semanticEvidenceMode: "PRODUCTION" }, { requireCritic: false }, { requireRemoteAi: false },
    { maxSourceBytes: 512 * 1024 * 1024 }, { maxExpandedBytes: 513 * 1024 * 1024 }, { maxArtifactBytes: 512 * 1024 * 1024 }, { extra: true }]) {
    assert.equal(validPolicy({ ...ociPolicy, ...edit }), false);
  }
  assert.equal(validPolicy({ ...defaultPolicy, maxArtifactBytes: 100 * 1024 * 1024 }), false);
  const descriptor = { sourceBytes: 100 * 1024 * 1024, layerArchiveBytes: 256 * 1024 * 1024, exportArchiveBytes: 256 * 1024 * 1024 };
  assert.doesNotThrow(() => assertRuntimeBudget(source, ociPolicy, descriptor));
  for (const edit of [{ sourceBytes: descriptor.sourceBytes + 1 }, { exportArchiveBytes: descriptor.exportArchiveBytes + 1 }, { layerArchiveBytes: -1 }, { sourceBytes: -1 }, { exportArchiveBytes: 0.5 }]) {
    assert.throws(() => assertRuntimeBudget(source, ociPolicy, { ...descriptor, ...edit }), /OCI_RUNTIME_BUDGET_EXCEEDED/);
  }
  assert.throws(() => assertRuntimeBudget({ metadata: { sourceBytes: 101 * 1024 * 1024 } }, ociPolicy), /OCI_SOURCE_BUDGET_EXCEEDED/);
  // No independent runtime proof: phase completion never falls through to legacy PASS.
  assert.equal(policyVerdict({ files: {} }, { scanStatus: "PASSED" }, ociPolicy), "ABSTAIN");
  assert.equal(policyVerdict({ files: { "oci/binding.json": "{}" } }, { scanStatus: "PASSED" }, defaultPolicy), "ABSTAIN");
});

test("OCI configuration is explicit local operator state, pins installed anchors and defaults disabled", async () => {
  assert.deepEqual(checkedOciConfig(config), config);
  for (const edit of [{ baseImageDigest: "alpine:latest" }, { databaseDir: "relative" }, { root: "arbitrary" }, { platform: { os: "linux", architecture: "unknown" } }]) {
    assert.throws(() => checkedOciConfig({ ...config, ...edit } as any), /INVALID_OCI_CONFIG/);
  }
  const local = await ociTrust(config), proof = { anchors: local, platform: config.platform };
  assert.equal(await checkedOciTrust(proof, config), proof);
  assert.equal(await checkedOciTrust(proof), undefined);
  assert.equal(await checkedOciTrust({ ...proof, anchors: { ...local, observerDigest: digest } }, config), undefined);
  const env = { CONTROL_PLANE_ENABLED: "true", CONTROL_PLANE_CREDENTIALS: JSON.stringify([{ tenantId: tenant, token, role: "operator" }]), CONTROL_EVIDENCE_KEY: "1".repeat(64),
    CONTROL_OCI_ENABLED: "true", CONTROL_SANDBOX_MODE: "docker", CONTROL_OCI_BASE_DIGEST: digest, CONTROL_OCI_BASE_CATALOGUE_DIGEST: digest,
    CONTROL_OCI_TRIVY_DIGEST: digest, CONTROL_OCI_DATABASE_DIR: config.databaseDir, CONTROL_OCI_DATABASE_DIGEST: digest, CONTROL_OCI_SINK_DIGEST: digest, CONTROL_OCI_ARCHITECTURE: "amd64" };
  assert.deepEqual(controlConfig(env)?.ociRuntime, config);
  assert.equal(controlConfig({ ...env, CONTROL_OCI_ENABLED: "false" })?.ociRuntime, undefined);
  assert.throws(() => controlConfig({ ...env, CONTROL_SANDBOX_MODE: "" }), /OCI_DOCKER_REQUIRED/);
  assert.throws(() => controlConfig({ ...env, CONTROL_OCI_TRIVY_DIGEST: "trivy:latest" }), /INVALID_OCI_CONFIG/);
});

test("OCI API reuses tenant ACL, quota/idempotency, exact source/profile and frozen retry configuration", async () => {
  const store = await ControlStore.open();
  const options: ControlOptions = { store, credentials: [{ tenantId: tenant, token, role: "operator" }, { tenantId: tenant, token: reader, role: "reader" }, { tenantId: "other", token: other, role: "operator" }],
    artifactPath: "unused", evidencePath: "unused", evidenceKey: "1".repeat(64), ociRuntime: structuredClone(config), scannerOptions: { sandbox: "docker", allowRemoteAi: false } };
  const app = await buildApp({ adminApiToken: "legacy-private-admin-token", scannerApiToken: "legacy-private-scanner-token", controlPlane: options });
  try {
    await store.put(tenant, "release", source.releaseId, source);
    const policy = { ...ociPolicy, maxQueuedScans: 1 }; await store.put(tenant, "policy", hash(policy), { document: policy });
    const request = (key: string, body: any = { policyHash: hash(policy) }, bearer = token) => app.inject({ method: "POST", url: `/v1/releases/${source.releaseId}/prepare`,
      headers: { authorization: `Bearer ${bearer}`, "idempotency-key": key }, payload: body });
    assert.equal((await request("wrong", undefined, "wrong")).statusCode, 401);
    assert.equal((await request("reader", undefined, reader)).statusCode, 403); assert.equal((await request("other", undefined, other)).statusCode, 404);
    for (const field of ["image", "root", "databaseDir", "baseImageDigest", "trivyImageDigest", "probePlan", "aiUrl", "aiToken", "semanticEvidenceMode"]) {
      assert.equal((await request(`extra-${field}`, { policyHash: hash(policy), [field]: "untrusted" })).statusCode, 400);
    }
    assert.equal((await request("npm-policy", { policyHash: hash(preparedPolicy) })).statusCode, 400);
    const first = await request("same"); assert.equal(first.statusCode, 202, first.body);
    const id = first.json().preparation.preparationId;
    assert.equal((await request("same")).json().preparation.preparationId, id);
    assert.equal((await request("quota")).statusCode, 429);
    const listed = (await app.inject({ url: "/v1/preparations", headers: { authorization: `Bearer ${reader}` } })).body;
    for (const privateValue of [config.databaseDir, source.artifactDir, "observerDigest", "trustedConfig", "leaseOwner", token]) assert.ok(!listed.includes(privateValue));
    assert.deepEqual(await store.get(tenant, "release", source.releaseId), source);
    assert.equal((await app.inject({ method: "POST", url: "/v1/scans", headers: { authorization: `Bearer ${token}`, "idempotency-key": "raw-oci-profile" },
      payload: { releaseId: source.releaseId, policyHash: hash(policy) } })).statusCode, 409);
    const job = (await claimPreparation(store, "contract-worker"))!;
    await store.query("UPDATE cp_preparations SET attempts=max_attempts WHERE preparation_id=?", [id]);
    await failPreparation(store, { ...job, attempts: job.maxAttempts }, "contract-worker", "WORKER_LOST", true, 0);
    const retry = (bearer = token, body?: any) => app.inject({ method: "POST", url: `/v1/preparations/${id}/retry`, headers: { authorization: `Bearer ${bearer}` }, ...(body ? { payload: body } : {}) });
    assert.equal((await retry(reader)).statusCode, 403); assert.equal((await retry(other)).statusCode, 404);
    assert.equal((await retry(token, { image: "untrusted" })).statusCode, 400);
    options.ociRuntime!.databaseDigest = `sha256:${"b".repeat(64)}`;
    assert.equal((await retry()).statusCode, 409); options.ociRuntime!.databaseDigest = digest;
    assert.equal((await retry()).statusCode, 200);
    assert.equal((await preparations(store, tenant, id))[0].status, "QUEUED");
    options.ociRuntime = undefined; assert.equal((await request("disabled")).statusCode, 503);
  } finally { await app.close(); }
});

async function syntheticOciEvidence() {
  const local = await ociTrust(config), { databaseDir: _directory, platform: _platform, ...anchors } = local;
  const tools = [{ name: "synthetic_tool", description: "private-synthetic-description", inputSchema: { type: "object" } }];
  const descriptor = { schemaVersion: "mcpshield.oci-runtime.v1", profile: "oci-container-v1", stage: "OBSERVED", budgetProfile: OCI_SOURCE_BUDGET_PROFILE,
    sourceBytes: 1000, layerArchiveBytes: 2048, exportArchiveBytes: 2048, sourceTreeDigest: digest, sourceIndexDigest: digest, manifestDigest: digest, configDigest: digest,
    platform: config.platform, finalImageDigest: digest, imageDigestKind: "DOCKER_IMAGE_CONFIG_ID", rootfsDigest: digest,
    entrypoint: { requestedPath: "/bin/sh", resolvedPath: "/bin/busybox", contentDigest: digest, linkChainDigest: digest }, argv: ["/bin/sh", "/server.sh"],
    workingDirectory: "/", environmentDigest: digest, toolSurfaceHash: toolSurfaceHash(tools), policy: OCI_OBSERVATION_POLICY };
  const binding = createOciReleaseBinding({ sourceReleaseId: source.releaseId, descriptor, executionPolicy: ociExecutionPolicy(anchors) });
  const documents = { "oci/binding.json": binding, "prepared/source-identity.json": sourceIdentity, "runtime/tools.json": tools,
    "runtime/oci-descriptor.json": descriptor, "runtime/execution-policy.json": binding.executionPolicy };
  return { documents, binding, tools, descriptor, anchors };
}
test("OCI encrypted bundle binds source and complete tools independently without accepting Node or foreign identities", async () => {
  const { documents, binding, tools, descriptor } = await syntheticOciEvidence();
  const bundle = createEvidenceBundle(documents), checked = checkedOciEvidence(bundle);
  assert.notEqual(checked.identity.releaseId, source.releaseId); assert.deepEqual(checked.tools, tools);
  assert.deepEqual(checkedOciEvidence(bundle, { ...checked.identity, artifactDigest: binding.artifactDigest, manifestDigest: binding.manifestDigest, toolSurfaceHash: binding.toolSurfaceHash }).binding, binding);
  assert.throws(() => checkedOciEvidence(bundle, source), /PREPARED_RELEASE_IDENTITY_MISMATCH/);
  assert.throws(() => checkedPreparedEvidence(bundle), /PREPARED_EVIDENCE_IDENTITY_MISMATCH/);
  for (const edit of [{ "runtime/tools.json": [] }, { "runtime/oci-descriptor.json": { ...descriptor, argv: ["/bin/evil"] } },
    { "prepared/source-identity.json": { ...sourceIdentity, toolId: `0x${"f".repeat(64)}` } }, { "prepared/binding.json": binding }]) {
    assert.throws(() => checkedOciEvidence(createEvidenceBundle({ ...documents, ...edit })), /IDENTITY_MISMATCH/);
  }
});

test("OCI worker creates distinct encrypted identities, preserves borrowed images and never equates completion with approval", async () => {
  const fixture = await syntheticOciEvidence(), dir = await mkdtemp(join(tmpdir(), "mcpshield-oci-worker-"));
  const store = await ControlStore.open(); let cleanups = 0, borrowedCleanups = 0, inspections = 0;
  const options: ControlOptions = { store, credentials: [{ tenantId: tenant, token, role: "operator" }, { tenantId: tenant, token: reader, role: "reader" }],
    artifactPath: dir, evidencePath: dir, evidenceKey: "1".repeat(64), ociRuntime: config, scannerOptions: { sandbox: "docker", allowRemoteAi: false },
    inspectOciRuntime: async () => { inspections++; return { anchors: fixture.anchors, platform: config.platform }; } };
  // Explicit synthetic identity/daemon double. No actual image or AI quality claim and no PASS possible.
  const output = (input: any, owned: boolean) => {
    const result = { schemaVersion: "1.0.0", scanId: input.scanId, releaseId: source.legacyReleaseId, artifactDigest: fixture.binding.artifactDigest,
      toolSurfaceHash: fixture.binding.toolSurfaceHash, scanStatus: "INCONCLUSIVE", findings: [], evidenceHash: `0x${"1".repeat(64)}`, source: "MOCK" };
    return { result, binding: fixture.binding, analysis: { profile: ociPolicy.profile, verdict: "ABSTAIN", issues: ["SYNTHETIC_TEST_NOT_EXECUTED"] },
      bundle: createEvidenceBundle({ ...fixture.documents, "report.json": result }), runtimeOwnership: owned ? "OWNED" : "BORROWED",
      runtimeTag: owned ? `mcpshield-oci-${randomUUID()}:local` : null, cleanup: async () => { if (owned) cleanups++; else borrowedCleanups++; } };
  };
  options.prepareOciRuntime = async input => {
    assert.deepEqual(Object.keys(input.preparation).sort(), ["platform", "root", "sourceTreeDigest"]);
    assert.equal(input.preparation.root, source.artifactDir); assert.deepEqual(input.trust, config);
    return output(input, false);
  };
  const app = await buildApp({ adminApiToken: "legacy-private-admin-token", scannerApiToken: "legacy-private-scanner-token", controlPlane: options });
  const auth = { authorization: `Bearer ${token}` }, request = (key: string) => app.inject({ method: "POST", url: `/v1/releases/${source.releaseId}/prepare`,
    headers: { ...auth, "idempotency-key": key }, payload: { policyHash: hash(ociPolicy) } });
  try {
    await store.put(tenant, "release", source.releaseId, source);
    const jobId = (await request("borrowed")).json().preparation.preparationId;
    await runPreparationWorkerOnce(store, options);
    const [job] = await preparations(store, tenant, jobId);
    assert.equal(job.status, "COMPLETED", JSON.stringify(job.lastError)); assert.equal(job.result?.verdict, "ABSTAIN");
    const derived = await store.get(tenant, "release", job.result!.releaseId), scan = await store.scan(tenant, job.result!.scanId);
    assert.equal(derived?.sourceType, "prepared-oci"); assert.equal(derived?.runtimeOwnership, "BORROWED"); assert.equal(derived?.runtimeTag, null);
    assert.equal(derived?.status, "UNVERIFIED"); assert.notEqual(derived?.releaseId, source.releaseId);
    assert.equal(scan?.result?.state, "REVIEW_REQUIRED"); assert.equal(scan?.result?.semanticEvidenceMode, "LOCAL_CONTRACT_TEST");
    assert.equal(scan?.result?.providerQuality, "PROVIDER_QUALITY_NOT_MEASURED"); assert.equal(borrowedCleanups, 0);
    const exported = await app.inject({ url: `/v1/releases/${derived!.releaseId}/gateway-config`, headers: auth });
    assert.equal(exported.statusCode, 200); assert.deepEqual(exported.json().binding, fixture.binding); assert.deepEqual(exported.json().tools, fixture.tools);
    for (const path of ["/v1/scans", "/v1/releases", "/v1/preparations"]) {
      const response = await app.inject({ url: path, headers: { authorization: `Bearer ${reader}` } });
      for (const secret of ["ociRuntimeTrust", "private-synthetic-description", config.databaseDir, "runtimeTag", "evidenceKey", "observerDigest"]) assert.ok(!response.body.includes(secret), `${path} ${secret}`);
      assert.ok(response.body.includes("LOCAL_CONTRACT_TEST"));
    }
    options.prepareOciRuntime = async input => output(input, true);
    await request("duplicate-owned"); await runPreparationWorkerOnce(store, options);
    assert.equal(cleanups, 1, "the duplicate helper owns only its new UUID tag");
    assert.equal((await store.get(tenant, "release", derived!.releaseId))?.runtimeOwnership, "BORROWED");
    options.prepareOciRuntime = async input => ({ ...output(input, true), cleanup: async () => { throw new Error("private Docker error must never escape"); } });
    const cleanupJob = (await request("duplicate-cleanup-failed")).json().preparation.preparationId;
    await runPreparationWorkerOnce(store, options);
    assert.equal((await preparations(store, tenant, cleanupJob))[0].status, "COMPLETED");
    const [pendingCleanup] = await store.list(tenant, "runtimeCleanup");
    assert.equal(pendingCleanup.code, "PREPARATION_CLEANUP_FAILED"); assert.match(pendingCleanup.runtimeTag, /^mcpshield-oci-/);
    assert.equal(pendingCleanup.status, "OPERATOR_RETRY_REQUIRED");
    const publicEvents = await app.inject({ url: "/v1/events", headers: { authorization: `Bearer ${reader}` } });
    assert.ok(publicEvents.body.includes("PREPARATION_CLEANUP_FAILED"));
    assert.doesNotMatch(publicEvents.body, /mcpshield-oci-|private Docker error|runtimeTag/);
    options.scanOciRuntime = async input => { assert.equal(input.expectedDescriptorDigest, fixture.binding.descriptorDigest); return output(input, false); };
    const rescan = () => app.inject({ method: "POST", url: "/v1/scans", headers: { ...auth, "idempotency-key": randomUUID() },
      payload: { releaseId: derived!.releaseId, policyHash: hash(ociPolicy) } });
    const second = await rescan(); assert.equal(second.statusCode, 202);
    await runControlWorkerOnce(store, options); assert.equal((await store.scan(tenant, second.json().scan.scanId))?.result?.verdict, "ABSTAIN");
    assert.equal(inspections, 4, "every borrowed execution rechecks native identity");
    options.inspectOciRuntime = async () => { throw new Error("OCI_RUNTIME_IMAGE_MISSING"); };
    const unavailable = await rescan(); await runControlWorkerOnce(store, options);
    assert.equal((await store.scan(tenant, unavailable.json().scan.scanId))?.status, "DEAD_LETTER");
    assert.equal((await store.scan(tenant, unavailable.json().scan.scanId))?.lastError?.code, "OCI_RUNTIME_IMAGE_MISSING");
    assert.deepEqual(await store.get(tenant, "release", source.releaseId), source);
  } finally { await app.close(); await rm(dir, { recursive: true, force: true }); }
});

test("OCI worker fences stale leases/configuration, rejects ambiguous ownership and enforces descriptor budgets before finalization", async () => {
  for (const mode of ["stale", "config", "ownership", "budget"]) {
    const fixture = await syntheticOciEvidence(), dir = await mkdtemp(join(tmpdir(), "mcpshield-oci-fence-")), store = await ControlStore.open();
    let cleaned = 0, executed = 0;
    const options: ControlOptions = { store, credentials: [{ tenantId: tenant, token, role: "operator" }], artifactPath: dir, evidencePath: dir, evidenceKey: "1".repeat(64),
      ociRuntime: structuredClone(config), scannerOptions: { sandbox: "docker", allowRemoteAi: false },
      inspectOciRuntime: async () => ({ anchors: fixture.anchors, platform: config.platform }) };
    const app = await buildApp({ adminApiToken: "legacy-private-admin-token", scannerApiToken: "legacy-private-scanner-token", controlPlane: options });
    try {
      await store.put(tenant, "release", source.releaseId, source);
      const policy = mode === "budget" ? { ...ociPolicy, maxExpandedBytes: 1024 } : ociPolicy;
      await store.put(tenant, "policy", hash(policy), { document: policy });
      const response = await app.inject({ method: "POST", url: `/v1/releases/${source.releaseId}/prepare`, headers: { authorization: `Bearer ${token}`, "idempotency-key": mode },
        payload: { policyHash: hash(policy) } });
      assert.equal(response.statusCode, 202); const jobId = response.json().preparation.preparationId;
      if (mode === "config") options.ociRuntime!.databaseDigest = `sha256:${"b".repeat(64)}`;
      options.prepareOciRuntime = async input => {
        executed++;
        if (mode === "stale") await store.query("UPDATE cp_preparations SET lease_expires_at=? WHERE preparation_id=?", [new Date(Date.now() - 1).toISOString(), jobId]);
        const result = { schemaVersion: "1.0.0", scanId: input.scanId, releaseId: source.legacyReleaseId, artifactDigest: fixture.binding.artifactDigest,
          toolSurfaceHash: fixture.binding.toolSurfaceHash, scanStatus: "INCONCLUSIVE", findings: [], evidenceHash: `0x${"1".repeat(64)}`, source: "MOCK" };
        return { binding: fixture.binding, result, bundle: createEvidenceBundle({ ...fixture.documents, "report.json": result }),
          runtimeOwnership: mode === "ownership" ? "UNKNOWN" : "OWNED", runtimeTag: `mcpshield-oci-${randomUUID()}:local`, cleanup: async () => { cleaned++; } };
      };
      await runPreparationWorkerOnce(store, options);
      const [job] = await preparations(store, tenant, jobId);
      assert.equal((await store.scans(tenant)).length, 0); assert.equal((await store.list(tenant, "release")).length, 1);
      assert.equal(executed, mode === "config" ? 0 : 1); assert.equal(cleaned, mode === "config" ? 0 : 1);
      assert.equal(job.status, mode === "stale" ? "RUNNING" : "DEAD_LETTER");
      if (mode !== "stale") assert.equal(job.lastError?.code, { config: "PREPARATION_CONFIG_CHANGED", ownership: "PREPARED_IMAGE_OWNERSHIP_MISSING", budget: "OCI_RUNTIME_BUDGET_EXCEEDED" }[mode]);
    } finally { await app.close(); await rm(dir, { recursive: true, force: true }); }
  }
});
