import assert from "node:assert/strict";
import { test } from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync, verify, randomUUID } from "node:crypto";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { canonical, defaultPolicy, hash, loadEvidence, saveEvidence, type ControlOptions } from "../../apps/api/src/control-plane.js";
import { runControlWorkerOnce } from "../../apps/api/src/control-worker.js";
import { controlConfig } from "../../apps/api/src/control-config.js";
import { policyVerdict } from "../../apps/api/src/control-policy.js";
import { exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";
// @ts-expect-error Shared scanner is ESM JavaScript.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";

const digest = `sha256:${"a".repeat(64)}`, surface = `0x${"b".repeat(64)}`;
const mockResult = { artifactDigest: digest, toolSurfaceHash: surface, scanStatus: "PASSED", findings: [] };
const mockBundle = createEvidenceBundle({ "report.json": { ...mockResult, scope: "STATIC_AI_SANDBOX" }, "sandbox/events.json": { mode: "DOCKER", complete: true },
  "static/findings.json": [], "semantic/model-output.json": { findings: [] }, "sandbox/mcp.json": { complete: true } });
const root = mockBundle.manifest.root;
const release = { ...exactReleaseIdentity({ toolId: "npm:mail-mcp", artifactDigest: digest, manifestDigest: digest, toolSurfaceHash: surface }),
  artifactDigest: digest, manifestDigest: digest, toolSurfaceHash: surface, artifactDir: "unused", legacyReleaseId: "mail-mcp@1.0.0", status: "UNVERIFIED" };
const tenant = "test-tenant", token = "test-control-admin-token-0000001";
const auth = { authorization: `Bearer ${token}` };
async function setup() {
  const dir = await mkdtemp(join(tmpdir(), "mcpshield-control-"));
  const store = await ControlStore.open(join(dir, "control.sqlite"));
  const keys = generateKeyPairSync("ed25519");
  const options: ControlOptions = { store, credentials: [
    { tenantId: tenant, token, role: "admin" },
    { tenantId: tenant, token: "test-control-reader-token-00001", role: "reader" },
    { tenantId: "another-tenant", token: "test-control-other-token-000001", role: "admin" },
  ], evidencePath: join(dir, "evidence"), artifactPath: join(dir, "artifacts"), evidenceKey: "1".repeat(64),
  signingKey: keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(), signingKeyId: "test-key",
  chainDecision: async () => ({ status: "VERIFIED", source: "EVM", policyHash: hash(defaultPolicy), validUntil: new Date(Date.now() + 60000).toISOString(),
    validatorSetVersion: 1, chainId: 31337, registryContract: `0x${"1".repeat(40)}`, observedBlock: 100, blockHash: root }),
  scanArtifact: async () => ({ result: mockResult, bundle: mockBundle }),
  verifyEvidence: (bundle, expectedRoot) => bundle.manifest.root === expectedRoot,
  };
  const app = await buildApp({ adminApiToken: "legacy-admin-token", scannerApiToken: "legacy-scanner-token", controlPlane: options });
  await store.put(tenant, "release", release.releaseId, release);
  return { app, store, options, keys, close: async () => { await app.close(); await rm(dir, { recursive: true, force: true }); } };
}

test("v1 tenant ACL, policy-bound idempotent jobs, encrypted evidence and signed admission", async () => {
  const f = await setup();
  try {
    assert.equal((await f.app.inject({ url: "/v1/session" })).statusCode, 401);
    assert.equal((await f.app.inject({ url: `/v1/releases/${release.releaseId}`, headers: { authorization: "Bearer test-control-other-token-000001" } })).statusCode, 404);
    const payload = { releaseId: release.releaseId, policyHash: hash(defaultPolicy) };
    const submit = () => f.app.inject({ method: "POST", url: "/v1/scans", payload, headers: { ...auth, "idempotency-key": "one" } });
    const first = (await submit()).json();
    assert.equal((await submit()).json().scan.scanId, first.scan.scanId);
    assert.equal((await f.app.inject({ method: "POST", url: "/v1/scans", payload, headers: { authorization: "Bearer test-control-reader-token-00001", "idempotency-key": "reader" } })).statusCode, 403);
    assert.equal(await runControlWorkerOnce(f.store, f.options), true);
    const scan = (await f.app.inject({ url: `/v1/scans/${first.scan.scanId}`, headers: auth })).json().scan;
    assert.equal(scan.status, "COMPLETED");
    assert.equal(scan.result.reportRoot, root);
    assert.equal(scan.result.evidenceKey, undefined);
    assert.equal((await f.app.inject({ url: `/v1/scans/${first.scan.scanId}/evidence`, headers: { authorization: "Bearer test-control-reader-token-00001" } })).statusCode, 403);
    assert.equal((await f.app.inject({ url: `/v1/scans/${first.scan.scanId}/evidence`, headers: auth })).json().reportRoot, root);
    const admitted = (await f.app.inject({ method: "POST", url: "/v1/admission/check", headers: auth, payload: { ...payload, artifactDigest: digest, toolSurfaceHash: surface, mode: "strict", operationClass: "READ_PUBLIC" } })).json();
    assert.equal(admitted.decision, "ALLOW");
    assert.equal(verify(null, Buffer.from(canonical(admitted.snapshot)), f.keys.publicKey, Buffer.from(admitted.signature, "base64url")), true);
    const tampered = { ...admitted.snapshot, observedBlock: 101 };
    assert.equal(verify(null, Buffer.from(canonical(tampered)), f.keys.publicKey, Buffer.from(admitted.signature, "base64url")), false);
    f.options.chainDecision = async () => { throw new Error("unavailable"); };
    assert.equal((await f.app.inject({ method: "POST", url: "/v1/admission/check", headers: auth, payload: { ...payload, artifactDigest: digest, toolSurfaceHash: surface, mode: "strict", operationClass: "FINANCIAL" } })).json().reasonCode, "STATUS_UNAVAILABLE");
    const appeal = (await f.app.inject({ method: "POST", url: `/v1/releases/${release.releaseId}/appeals`, headers: auth, payload: { reason: "Please rescan this synthetic release", scanId: first.scan.scanId } })).json().appeal;
    assert.equal(appeal.status, "OPEN");
    const history = (await f.app.inject({ url: `/v1/releases/${release.releaseId}/history`, headers: auth })).json().items;
    assert.ok(history.some((event: any) => event.eventName === "evidence.accessed"));
    assert.ok(history.some((event: any) => event.eventName === "appeal.opened"));
  } finally { await f.close(); }
});

test("durable queue claims fence workers and retryable failures reach DLQ", async () => {
  const f = await setup();
  try {
    await f.store.enqueue(tenant, { releaseId: release.releaseId, policyHash: hash(defaultPolicy) }, "queue", "hash", "trace");
    const claims = await Promise.all([f.store.claim("worker-a"), f.store.claim("worker-b")]);
    assert.equal(claims.filter(Boolean).length, 1);
    let scan = claims.find(Boolean)!;
    assert.equal(await f.store.finish(scan, "wrong-owner", {}), false);
    for (let attempt = 0; attempt < 3; attempt++) {
      await f.store.fail(scan, scan.leaseOwner!, "WORKER_LOST", true, 0);
      if (attempt < 2) scan = (await f.store.claim("worker-a"))!;
    }
    const failed = await f.store.scan(tenant, scan.scanId);
    assert.equal(failed?.status, "DEAD_LETTER");
    assert.equal(failed?.attempts, 3);
    assert.equal(await f.store.retry(tenant, scan.scanId), true);
    assert.equal((await f.store.scan(tenant, scan.scanId))?.status, "QUEUED");
    const events = await f.store.events(tenant, scan.releaseId);
    assert.ok(events.some((event) => event.eventName === "scan.state.changed" && event.payload.status === "DEAD_LETTER"));
  } finally { await f.close(); }
});

test("policy guards stage coverage and idempotent retry survives an exhausted quota", async () => {
  const f = await setup();
  try {
    const invalid = await f.app.inject({ method: "POST", url: "/v1/policies", headers: auth, payload: { alias: "unsafe", document: { ...defaultPolicy, requiredTiers: ["static"] } } });
    assert.equal(invalid.statusCode, 400);
    const document = { ...defaultPolicy, maxQueuedScans: 1 };
    const policy = (await f.app.inject({ method: "POST", url: "/v1/policies", headers: auth, payload: { alias: "bounded", document } })).json().policy;
    const payload = { releaseId: release.releaseId, policyHash: policy.policyHash };
    const first = await f.app.inject({ method: "POST", url: "/v1/scans", headers: { ...auth, "idempotency-key": "first" }, payload });
    assert.equal(first.statusCode, 202);
    assert.equal((await f.app.inject({ method: "POST", url: "/v1/scans", headers: { ...auth, "idempotency-key": "first" }, payload })).json().deduplicated, true);
    assert.equal((await f.app.inject({ method: "POST", url: "/v1/scans", headers: { ...auth, "idempotency-key": "second" }, payload })).statusCode, 429);
  } finally { await f.close(); }
});

test("remote AI is server-only and requires an explicit allow flag, key and model", () => {
  const env = { CONTROL_PLANE_ENABLED: "true", CONTROL_PLANE_CREDENTIALS: JSON.stringify([{ tenantId: tenant, token, role: "admin" }]),
    CONTROL_EVIDENCE_KEY: "1".repeat(64), CONTROL_AI_PROVIDER: "openai", OPENAI_API_KEY: "synthetic-provider-key" };
  assert.deepEqual(controlConfig(env)!.scannerOptions, { sandbox: undefined, allowRemoteAi: false });
  assert.throws(() => controlConfig({ ...env, CONTROL_ALLOW_REMOTE_AI: "true" }), /KEY_AND_MODEL_REQUIRED/);
  const configured = controlConfig({ ...env, CONTROL_ALLOW_REMOTE_AI: "true", CONTROL_AI_MODEL: "explicit-test-model", CONTROL_SANDBOX_MODE: "docker" })!;
  assert.equal(configured.scannerOptions!.aiToken, env.OPENAI_API_KEY);
  assert.equal(configured.scannerOptions!.aiModel, "explicit-test-model");
  assert.equal(configured.scannerOptions!.sandbox, "docker");
  assert.throws(() => controlConfig({ ...env, CONTROL_ALLOW_REMOTE_AI: "true", CONTROL_AI_PROVIDER: "custom", CONTROL_AI_URL: "http://remote.test" }), /HTTPS_REQUIRED/);
});

test("validator policy cannot PASS incomplete MCP or unresolved critic evidence, or FAIL on AI alone", () => {
  const bundle = structuredClone(mockBundle);
  assert.equal(policyVerdict(bundle, mockResult), "PASS");
  bundle.files["semantic/model-output.json"] = JSON.stringify({ findings: [], execution: { status: "REVIEW_REQUIRED" } });
  assert.equal(policyVerdict(bundle, mockResult), "ABSTAIN");
  bundle.files["semantic/model-output.json"] = JSON.stringify({ findings: [], execution: { status: "LOCAL_FALLBACK" } });
  bundle.files["sandbox/mcp.json"] = JSON.stringify({ complete: false });
  assert.equal(policyVerdict(bundle, mockResult), "ABSTAIN");
  const aiResult = { ...mockResult, scanStatus: "FAILED", findings: [{ severity: "CRITICAL", deterministic: false, stage: "AI" }] };
  bundle.files["report.json"] = JSON.stringify(aiResult);
  assert.equal(policyVerdict(bundle, aiResult), "ABSTAIN");
  assert.throws(() => policyVerdict(bundle, { ...aiResult, findings: [] }), /EVIDENCE_RESULT_MISMATCH/);
});

test("AES-GCM evidence rejects tenant crossing and modified bytes", async () => {
  const f = await setup();
  try {
    const bundle = { manifest: { root }, secret: "synthetic-private-evidence" };
    const key = await saveEvidence(f.options, tenant, bundle);
    assert.deepEqual(await loadEvidence(f.options, tenant, key), bundle);
    await assert.rejects(loadEvidence(f.options, "other", key), /INTEGRITY/);
    const path = join(f.options.evidencePath, `${key}.bin`), bytes = await readFile(path);
    assert.equal(bytes.includes(Buffer.from(bundle.secret)), false);
    bytes[bytes.length - 1] ^= 1; await writeFile(path, bytes);
    await assert.rejects(loadEvidence(f.options, tenant, key), /INTEGRITY/);
  } finally { await f.close(); }
});

test("existing chain outbox upgrades without guessing its historical registry and reopens idempotently", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-migration-")), path = join(directory, "old.sqlite");
  const previous = new DatabaseSync(path);
  previous.exec(readFileSync(new URL("../../database/migrations/004_chain_outbox.sql", import.meta.url), "utf8"));
  previous.prepare("INSERT INTO cp_chain_actions(action_id,tenant_id,kind,payload,chain_id,relayer_address,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
    .run("legacy-action", tenant, "REGISTER_RELEASE", "{}", 1337, "historical-relayer", "2026-01-01", "2026-01-01");
  previous.close();
  try {
    for (let attempt = 0; attempt < 2; attempt++) {
      const upgraded = await ControlStore.open(path);
      try {
        const [action] = await upgraded.query("SELECT registry_address,state FROM cp_chain_actions WHERE action_id = ?", ["legacy-action"]);
        assert.equal(action.registry_address, null); assert.equal(action.state, "NEW");
      } finally { await upgraded.close(); }
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("real resolver to durable worker yields verified evidence without host execution", async () => {
  const f = await setup();
  try {
    f.options.scanArtifact = undefined; f.options.verifyEvidence = undefined;
    const resolved = await f.app.inject({ method: "POST", url: "/v1/releases/resolve", headers: auth, payload: { sourceType: "fixture", locator: "mail-mcp-1.0.0" } });
    assert.equal(resolved.statusCode, 201, resolved.body);
    const id = resolved.json().release.releaseId;
    const queued = await f.app.inject({ method: "POST", url: "/v1/scans", headers: { ...auth, "idempotency-key": "real-fixture" }, payload: { releaseId: id, policyHash: hash(defaultPolicy) } });
    assert.equal(queued.statusCode, 202, queued.body);
    await runControlWorkerOnce(f.store, f.options);
    const scan = await f.store.scan(tenant, queued.json().scan.scanId);
    assert.equal(scan?.status, "COMPLETED", JSON.stringify(scan?.lastError));
    assert.equal(scan?.result?.scanResult.scanStatus, "INCONCLUSIVE");
    const evidence = await f.app.inject({ url: `/v1/scans/${scan?.scanId}/evidence`, headers: auth });
    assert.equal(evidence.statusCode, 200, evidence.body);
    assert.equal(evidence.json().bundle.manifest.root, scan?.result?.reportRoot);
  } finally { await f.close(); }
});

test("PostgreSQL real adapter persists and atomically dequeues", { skip: !process.env.MCPSHIELD_POSTGRES_TEST_URL }, async () => {
  const opening = await Promise.all([ControlStore.open(process.env.MCPSHIELD_POSTGRES_TEST_URL), ControlStore.open(process.env.MCPSHIELD_POSTGRES_TEST_URL)]);
  await Promise.all(opening.map((connection) => connection.close()));
  const store = await ControlStore.open(process.env.MCPSHIELD_POSTGRES_TEST_URL);
  const tenantId = `pg-${randomUUID()}`;
  try {
    assert.equal(store.driver, "POSTGRESQL");
    const first = await store.enqueue(tenantId, { releaseId: release.releaseId, policyHash: hash(defaultPolicy) }, "once", "input", "trace");
    assert.equal((await store.enqueue(tenantId, { releaseId: release.releaseId, policyHash: hash(defaultPolicy) }, "once", "input", "trace")).deduplicated, true);
    const leased = await store.claim(tenantId);
    assert.equal(leased?.scanId, first.scan.scanId);
    assert.equal(await store.finish(leased!, tenantId, { check: "POSTGRESQL" }), true);
    assert.equal((await store.scan(tenantId, first.scan.scanId))?.status, "COMPLETED");
  } finally {
    await store.query("DELETE FROM cp_scans WHERE tenant_id = ?", [tenantId]);
    await store.close();
  }
});
