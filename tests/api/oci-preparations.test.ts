import assert from "node:assert/strict";
import { test } from "node:test";
import { resolve } from "node:path";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { hash, type ControlOptions } from "../../apps/api/src/control-plane.js";
import { assertRuntimeBudget, defaultPolicy, ociPolicy, policyVerdict, preparedPolicy, validPolicy } from "../../apps/api/src/control-policy.js";
import { checkedOciConfig, checkedOciTrust, ociTrust, type OciConfig } from "../../apps/api/src/oci-config.js";
import { controlConfig } from "../../apps/api/src/control-config.js";
import { claimPreparation, failPreparation, preparations } from "../../apps/api/src/preparation-store.js";
import { checkedOciEvidence, checkedPreparedEvidence } from "../../apps/api/src/prepared-evidence.js";
import { exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";
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
  // This checkpoint deliberately has no approval implementation: phase completion never falls through to legacy PASS.
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

test("OCI encrypted bundle binds source and complete tools independently without accepting Node or foreign identities", async () => {
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
