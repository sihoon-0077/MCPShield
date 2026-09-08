import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { hash, type ControlOptions } from "../../apps/api/src/control-plane.js";
import { defaultPolicy, policyVerdict, preparedPolicy, validPolicy } from "../../apps/api/src/control-policy.js";
import { controlConfig } from "../../apps/api/src/control-config.js";
import { preparedTrust } from "../../apps/api/src/prepared-config.js";
import { claimPreparation, failPreparation, preparations } from "../../apps/api/src/preparation-store.js";
import { exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";
import { runPreparationWorkerOnce } from "../../apps/api/src/preparation-worker.js";
import { checkedPreparedEvidence } from "../../apps/api/src/prepared-evidence.js";
// @ts-expect-error Shared ESM binding helper.
import { createPreparedReleaseBinding, preparedExecutionPolicy } from "../../services/scanner/src/prepared-binding.mjs";
// @ts-expect-error Shared ESM evidence helper.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";
// @ts-expect-error Shared ESM surface identity helper.
import { toolSurfaceHash } from "../../services/scanner/src/scanner.mjs";

const tenant = "prepared-test", token = "prepared-test-operator-token-0001", other = "prepared-other-operator-token-0001", reader = "prepared-test-reader-token-0001";
const auth = { authorization: `Bearer ${token}` };
const identity = exactReleaseIdentity({ toolId: "npm:prepared-test", artifactDigest: `sha256:${"a".repeat(64)}`, manifestDigest: `sha256:${"b".repeat(64)}`, toolSurfaceHash: `0x${"c".repeat(64)}` });
const source = { ...identity, artifactDigest: `sha256:${"a".repeat(64)}`, manifestDigest: `sha256:${"b".repeat(64)}`, toolSurfaceHash: `0x${"c".repeat(64)}`,
  sourceType: "npm", artifactDir: "unused-private-source-path", legacyReleaseId: "prepared-test@1.0.0", status: "UNVERIFIED" };
async function setup() {
  const store = await ControlStore.open();
  const options: ControlOptions = { store, credentials: [{ tenantId: tenant, token, role: "operator" }, { tenantId: "other", token: other, role: "operator" }, { tenantId: tenant, token: reader, role: "reader" }],
    artifactPath: "unused", evidencePath: "unused", evidenceKey: "1".repeat(64), scannerOptions: { sandbox: "docker", allowRemoteAi: false },
    preparedRuntime: { builderImageDigest: `sha256:${"d".repeat(64)}`, platform: { os: "linux", architecture: "amd64" } } };
  const app = await buildApp({ adminApiToken: "legacy-private-admin-token", scannerApiToken: "legacy-private-scanner-token", controlPlane: options });
  await store.put(tenant, "release", source.releaseId, source);
  const request = (key: string, body: any = { policyHash: hash(preparedPolicy) }, bearer = token, releaseId = source.releaseId) => app.inject({ method: "POST", url: `/v1/releases/${releaseId}/prepare`,
    headers: { authorization: `Bearer ${bearer}`, "idempotency-key": key }, payload: body });
  return { app, store, options, request };
}
test("prepared API enforces ACL, strict profile and server-only configuration", async () => {
  const f = await setup();
  try {
    assert.equal((await f.request("auth", undefined, "wrong")).statusCode, 401);
    assert.equal((await f.request("reader", undefined, reader)).statusCode, 403);
    assert.equal((await f.request("tenant", undefined, other)).statusCode, 404);
    assert.equal((await f.request("policy", { policyHash: hash(defaultPolicy) })).statusCode, 400);
    for (const field of ["builderImageDigest", "platform", "root", "binName", "image", "probePlan", "aiToken", "aiUrl"]) {
      assert.equal((await f.request(`field-${field}`, { policyHash: hash(preparedPolicy), [field]: "untrusted" })).statusCode, 400);
    }
    assert.equal((await f.request("")).statusCode, 400);
    const first = await f.request("same"); assert.equal(first.statusCode, 202);
    const job = first.json().preparation;
    assert.equal(job.status, "QUEUED"); assert.equal(job.result, undefined);
    for (const value of ["unused-private-source-path", "builderImageDigest", "leaseOwner", "request", token, "collectorDigest"]) assert.ok(!first.body.includes(value));
    assert.equal((await f.request("same")).json().preparation.preparationId, job.preparationId);
    f.options.preparedRuntime!.builderImageDigest = `sha256:${"e".repeat(64)}`;
    assert.equal((await f.request("same")).json().preparation.preparationId, job.preparationId);
    const [stored] = await preparations(f.store, tenant, job.preparationId);
    assert.notEqual(stored.configHash, hash(preparedTrust(f.options.preparedRuntime!)));
    assert.equal((await f.app.inject({ url: `/v1/preparations/${job.preparationId}`, headers: { authorization: `Bearer ${other}` } })).statusCode, 404);
    assert.equal((await f.app.inject({ url: `/v1/preparations/${job.preparationId}`, headers: { authorization: `Bearer ${reader}` } })).statusCode, 200);
    assert.deepEqual(await f.store.get(tenant, "release", source.releaseId), source);
    assert.equal((await f.app.inject({ method: "POST", url: "/v1/scans", headers: { ...auth, "idempotency-key": "cross-profile" }, payload: { releaseId: source.releaseId, policyHash: hash(preparedPolicy) } })).statusCode, 409);
    const changedPolicy = { ...preparedPolicy, validitySeconds: 120 }; await f.store.put(tenant, "policy", hash(changedPolicy), { document: changedPolicy });
    assert.equal((await f.request("same", { policyHash: hash(changedPolicy) })).statusCode, 409);
    f.options.preparedRuntime = undefined; assert.equal((await f.request("disabled")).statusCode, 503);
  } finally { await f.app.close(); }
});
test("preparation and scan quotas are atomic across concurrent requests and tenant isolation", async () => {
  const f = await setup();
  try {
    const policy = { ...preparedPolicy, maxDailyScans: 2, maxQueuedScans: 1 };
    await f.store.put(tenant, "policy", hash(policy), { document: policy });
    const results = await Promise.all(Array.from({ length: 8 }, (_, i) => f.request(`quota-${i}`, { policyHash: hash(policy) })));
    assert.equal(results.filter((result) => result.statusCode === 202).length, 1);
    assert.equal(results.filter((result) => result.statusCode === 429).length, 7);
    assert.equal((await f.store.scanUsage(tenant)).queued, 1);
    const strictLegacy = { ...defaultPolicy, maxQueuedScans: 1 }; await f.store.put(tenant, "policy", hash(strictLegacy), { document: strictLegacy });
    assert.equal((await f.app.inject({ method: "POST", url: "/v1/scans", headers: { ...auth, "idempotency-key": "shared" }, payload: { releaseId: source.releaseId, policyHash: hash(strictLegacy) } })).statusCode, 429);
    await f.store.put("other", "release", source.releaseId, source);
    const key = results.findIndex((result) => result.statusCode === 202);
    assert.equal((await f.request(`quota-${key}`, undefined, other)).statusCode, 202);
    const job = await claimPreparation(f.store, "worker-a"); assert.ok(job);
    assert.equal(await failPreparation(f.store, job, "worker-a", "UNSUPPORTED_SOURCE", false), true);
    assert.equal((await f.request("daily-2", { policyHash: hash(policy) })).statusCode, 202);
    const jobs = await preparations(f.store, tenant), current = jobs.find((item) => item.status === "QUEUED")!;
    await f.store.query("UPDATE cp_preparations SET state='DEAD_LETTER' WHERE preparation_id=?", [current.preparationId]);
    assert.equal((await f.request("daily-3", { policyHash: hash(policy) })).statusCode, 429);
  } finally { await f.app.close(); }
});
test("preparation durable leases fence workers, expire safely and freeze configuration on retry", async () => {
  const f = await setup();
  try {
    const id = (await f.request("lease")).json().preparation.preparationId;
    const claimed = await Promise.all([claimPreparation(f.store, "one"), claimPreparation(f.store, "two")]);
    assert.equal(claimed.filter(Boolean).length, 1); let job = claimed.find(Boolean)!;
    assert.equal(await failPreparation(f.store, job, "foreign-owner", "WORKER_LOST", true, 0), false);
    for (let attempt = 0; attempt < 3; attempt++) {
      assert.equal(await failPreparation(f.store, job, job.leaseOwner!, "WORKER_LOST", true, 0), true);
      if (attempt < 2) job = (await claimPreparation(f.store, "one"))!;
    }
    assert.equal((await preparations(f.store, tenant, id))[0].status, "DEAD_LETTER");
    const retry = (bearer = token, body?: any) => f.app.inject({ method: "POST", url: `/v1/preparations/${id}/retry`, headers: { authorization: `Bearer ${bearer}` }, ...(body ? { payload: body } : {}) });
    assert.equal((await retry(reader)).statusCode, 403); assert.equal((await retry(other)).statusCode, 404);
    assert.equal((await retry(token, { image: "untrusted" })).statusCode, 400);
    f.options.preparedRuntime!.builderImageDigest = `sha256:${"e".repeat(64)}`;
    assert.equal((await retry()).statusCode, 409);
    f.options.preparedRuntime!.builderImageDigest = `sha256:${"d".repeat(64)}`;
    assert.equal((await retry()).statusCode, 200);
    job = (await claimPreparation(f.store, "three"))!;
    await f.store.query("UPDATE cp_preparations SET lease_expires_at=?,attempts=3 WHERE preparation_id=?", [new Date(Date.now() - 1).toISOString(), id]);
    assert.equal(await failPreparation(f.store, job, "three", "WORKER_LOST", true), false);
    assert.equal(await claimPreparation(f.store, "four"), undefined);
    assert.equal((await preparations(f.store, tenant, id))[0].lastError?.code, "WORKER_LOST");
    assert.ok((await f.store.events(tenant)).some((event) => event.eventName === "preparation.retried"));
    const policy = await f.store.get(tenant, "policy", hash(preparedPolicy)); await f.store.put(tenant, "policy", hash(preparedPolicy), { ...policy, deprecatedAt: new Date().toISOString() }, true);
    assert.equal((await retry()).statusCode, 409);
  } finally { await f.app.close(); }
});
test("prepared policy and environment refuse weakening, implicit Docker or mutable builder tags", () => {
  assert.equal(validPolicy(preparedPolicy), true); assert.notEqual(hash(preparedPolicy), hash(defaultPolicy));
  assert.equal(policyVerdict({ files: {} }, {}, preparedPolicy), "ABSTAIN");
  for (const edit of [{ requireCritic: false }, { requireRemoteAi: false }, { profile: "pretend-profile" }, { extra: true }]) assert.equal(validPolicy({ ...preparedPolicy, ...edit }), false);
  const env = { CONTROL_PLANE_ENABLED: "true", CONTROL_PLANE_CREDENTIALS: JSON.stringify([{ tenantId: tenant, token, role: "operator" }]), CONTROL_EVIDENCE_KEY: "1".repeat(64),
    CONTROL_PREPARED_ENABLED: "true", CONTROL_SANDBOX_MODE: "docker", CONTROL_PREPARED_ARCHITECTURE: "amd64", CONTROL_PREPARED_BUILDER_DIGEST: `sha256:${"d".repeat(64)}` };
  assert.ok(controlConfig(env)?.preparedRuntime);
  assert.equal(controlConfig({ ...env, CONTROL_PREPARED_ENABLED: "false" })?.preparedRuntime, undefined);
  assert.throws(() => controlConfig({ ...env, CONTROL_SANDBOX_MODE: "" }), /PREPARED_DOCKER_REQUIRED/);
  assert.throws(() => controlConfig({ ...env, CONTROL_PREPARED_BUILDER_DIGEST: "node:latest" }), /INVALID_PREPARED_CONFIG/);
  assert.throws(() => controlConfig({ ...env, CONTROL_PREPARED_ARCHITECTURE: "unknown" }), /INVALID_PREPARED_CONFIG/);
});

function syntheticPreparedOutput(input: any, cleanup: () => Promise<void>) {
  const tools = [{ name: "private_synthetic_tool", description: "synthetic-private-tool-description", inputSchema: { type: "object" } }];
  const descriptor = { schemaVersion: "mcpshield.prepared-runtime.v1", stage: "CLOSURE_PREPARED", profile: "npm-closure-v1",
    sourceDigest: source.artifactDigest, sourceTreeDigest: source.artifactDigest, lockDigest: source.artifactDigest, lockOrigin: "SUPPLIED",
    builderImageDigest: input.trusted.builderImageDigest, platform: input.preparation.platform, finalImageDigest: `sha256:${"e".repeat(64)}`, toolSurfaceHash: toolSurfaceHash(tools),
    entrypoint: { path: "server.mjs", digest: source.artifactDigest }, argv: ["/usr/local/bin/node", "/app/server.mjs"],
    policy: { acquisitionNetwork: "REGISTRY_ONLY_SEPARATE", installNetwork: "NONE", installScripts: "DISABLED", executionNetwork: "INTERNAL_SYNTHETIC_PROXY", user: "NON_ROOT", rootFilesystem: "READ_ONLY" } };
  const binding = createPreparedReleaseBinding({ sourceReleaseId: source.releaseId, descriptor,
    executionPolicy: preparedExecutionPolicy({ collectorDigest: input.trusted.collectorDigest, observerDigest: input.trusted.observerDigest, egressAllowHosts: ["mail-api.local"] }) });
  const result = { schemaVersion: "1.0.0", scanId: input.scanId, releaseId: source.legacyReleaseId, artifactDigest: binding.artifactDigest,
    toolSurfaceHash: binding.toolSurfaceHash, scanStatus: "INCONCLUSIVE", findings: [], evidenceHash: `0x${"1".repeat(64)}`, source: "MOCK" };
  const analysis = { profile: preparedPolicy.profile, verdict: "ABSTAIN", issues: ["SYNTHETIC_CONTRACT_TEST_NOT_LIVE_DOCKER"] };
  return { binding, result, analysis, cleanup, runtimeTag: `mcpshield-runtime-${randomUUID()}:local`,
    bundle: createEvidenceBundle({ "report.json": { ...result, scope: "RESTRICTED_NODE_DOCKER_V1" }, "prepared/binding.json": binding,
      "runtime/tools.json": tools, "runtime/descriptor.json": descriptor, "runtime/execution-policy.json": binding.executionPolicy, "prepared/policy-review.json": analysis }) };
}
test("prepared worker atomically creates a distinct identity and encrypted scan without granting PASS", async () => {
  const f = await setup(), dir = await mkdtemp(join(tmpdir(), "mcpshield-prepared-worker-")); let cleaned = 0;
  f.options.evidencePath = dir;
  try {
    f.options.prepareRuntime = async (input) => {
      assert.equal(input.preparation.root, source.artifactDir); assert.equal(input.sourceReleaseId, source.releaseId);
      return syntheticPreparedOutput(input, async () => { cleaned++; });
    };
    const jobId = (await f.request("execute")).json().preparation.preparationId;
    assert.equal(await runPreparationWorkerOnce(f.store, f.options), true);
    const [job] = await preparations(f.store, tenant, jobId); assert.equal(job.status, "COMPLETED", JSON.stringify(job.lastError));
    assert.equal(job.result?.verdict, "ABSTAIN"); assert.notEqual(job.result?.releaseId, source.releaseId); assert.equal(cleaned, 0);
    const scan = await f.store.scan(tenant, job.result!.scanId); assert.equal(scan?.status, "COMPLETED"); assert.equal(scan?.result?.scanResult.scanId, scan?.scanId);
    assert.equal(scan?.result?.state, "REVIEW_REQUIRED"); assert.equal((await f.store.scanUsage(tenant)).today, 1);
    assert.deepEqual(await f.store.get(tenant, "release", source.releaseId), source);
    const releaseId = job.result!.releaseId;
    const release = await f.app.inject({ url: `/v1/releases/${releaseId}`, headers: auth });
    assert.equal(release.json().release.status, "UNVERIFIED");
    const exported = await f.app.inject({ url: `/v1/releases/${releaseId}/gateway-config`, headers: auth });
    assert.equal(exported.statusCode, 200); assert.equal(exported.json().schemaVersion, "mcpshield.gateway-prepared.v1");
    assert.equal(exported.json().tools[0].name, "private_synthetic_tool"); assert.equal(exported.headers["cache-control"], "no-store");
    for (const bearer of [reader, other]) assert.equal((await f.app.inject({ url: `/v1/releases/${releaseId}/gateway-config`, headers: { authorization: `Bearer ${bearer}` } })).statusCode, bearer === reader ? 403 : 404);
    const evidence = await f.app.inject({ url: `/v1/preparations/${jobId}/evidence`, headers: auth }); assert.equal(evidence.statusCode, 200);
    const bound = checkedPreparedEvidence(evidence.json().bundle); assert.equal(bound.identity.releaseId, releaseId);
    for (const path of ["/v1/releases", "/v1/scans", "/v1/preparations"]) {
      const body = (await f.app.inject({ url: path, headers: { authorization: `Bearer ${reader}` } })).body;
      for (const privateValue of ["synthetic-private-tool-description", "runtimeTag", "preparedEvidenceKey", "evidenceKey", "collectorDigest"]) assert.ok(!body.includes(privateValue), `${path} ${privateValue}`);
    }
    assert.equal((await f.app.inject({ url: `/v1/preparations/${jobId}/evidence`, headers: { authorization: `Bearer ${reader}` } })).statusCode, 403);
    await f.request("duplicate-image"); await runPreparationWorkerOnce(f.store, f.options); assert.equal(cleaned, 1);
  } finally { await f.app.close(); await rm(dir, { recursive: true, force: true }); }
});
test("prepared worker fails closed on no discovery, changed config/source and stale lease; only its own image is cleaned", async () => {
  for (const mode of ["no-binding", "config-changed", "source-changed", "stale-lease", "binding-tampered", "uncertain-commit"] as const) {
    const f = await setup(), dir = await mkdtemp(join(tmpdir(), "mcpshield-prepared-fence-")); f.options.evidencePath = dir; let cleaned = 0, calls = 0;
    try {
      const jobId = (await f.request(mode)).json().preparation.preparationId;
      if (mode === "config-changed") f.options.preparedRuntime!.builderImageDigest = `sha256:${"f".repeat(64)}`;
      f.options.prepareRuntime = async (input) => {
        calls++;
        const output = syntheticPreparedOutput(input, async () => { cleaned++; });
        if (mode === "no-binding") return { result: null, binding: null, bundle: null, analysis: { issues: ["PREPARED_DISCOVERY_REQUIRED"] }, cleanup: output.cleanup };
        if (mode === "source-changed") await f.store.put(tenant, "release", source.releaseId, { ...source, artifactDigest: `sha256:${"f".repeat(64)}` }, true);
        if (mode === "stale-lease") await f.store.query("UPDATE cp_preparations SET lease_expires_at=? WHERE preparation_id=?", [new Date(Date.now() - 1).toISOString(), jobId]);
        if (mode === "binding-tampered") output.binding.manifestDigest = source.artifactDigest;
        return output;
      };
      if (mode === "uncertain-commit") {
        const original = f.store.forTenant.bind(f.store);
        f.store.forTenant = async (tenantId, callback) => {
          const result = await original(tenantId, callback);
          if (result && typeof result === "object" && "transferred" in result) throw new Error("TRANSIENT_COMMIT_UNCERTAIN");
          return result;
        };
      }
      await runPreparationWorkerOnce(f.store, f.options);
      const [job] = await preparations(f.store, tenant, jobId), scans = await f.store.scans(tenant);
      assert.equal(calls, mode === "config-changed" ? 0 : 1);
      if (mode === "uncertain-commit") { assert.equal(job.status, "COMPLETED"); assert.equal(scans.length, 1); assert.equal(cleaned, 0); }
      else { assert.equal(scans.length, 0); assert.equal(cleaned, mode === "config-changed" ? 0 : 1); }
      if (mode === "no-binding") { assert.equal(job.result?.outcome, "INCONCLUSIVE"); assert.equal(job.status, "COMPLETED"); }
      else if (mode === "stale-lease") assert.equal(job.status, "RUNNING");
      else if (mode !== "uncertain-commit") assert.equal(job.status, "DEAD_LETTER");
    } finally { await f.app.close(); await rm(dir, { recursive: true, force: true }); }
  }
});
