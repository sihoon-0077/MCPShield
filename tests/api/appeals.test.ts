import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { hash, type ControlOptions } from "../../apps/api/src/control-plane.js";
import { defaultPolicy, preparedPolicy } from "../../apps/api/src/control-policy.js";
import { runControlWorkerOnce } from "../../apps/api/src/control-worker.js";
import { exactReleaseIdentity } from "../../packages/contracts-sdk/src/v2.js";
// @ts-expect-error Shared canonical evidence; synthetic PASS here tests queue reuse, not scanner efficacy.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";

const a = "appeal-a", b = "appeal-b", admin = "synthetic-appeal-admin-token", operator = "synthetic-appeal-operator-token";
const other = "synthetic-other-admin-token", reader = "synthetic-appeal-reader-token";
const digest = (letter: string) => `sha256:${letter.repeat(64)}`, surface = `0x${"b".repeat(64)}`;
const release = (letter: string, toolId = "npm:appeal-fixture") => ({
  ...exactReleaseIdentity({ toolId, artifactDigest: digest(letter), manifestDigest: digest(letter), toolSurfaceHash: surface }),
  artifactDigest: digest(letter), manifestDigest: digest(letter), toolSurfaceHash: surface, artifactDir: letter,
  status: "REVOKED", policyHash: hash(defaultPolicy), reportRoot: `0x${"a".repeat(64)}`, validUntil: null,
  chain: { source: "SYNTHETIC_STATE_PRESERVATION_TEST" }, sourceType: "fixture", legacyReleaseId: "appeal-fixture@1.0.0",
});
async function setup(databaseUrl?: string) {
  const dir = await mkdtemp(join(tmpdir(), "mcpshield-appeals-")), store = await ControlStore.open(databaseUrl);
  const tenantA = databaseUrl ? `appeal-a-${randomUUID()}` : a, tenantB = databaseUrl ? `appeal-b-${randomUUID()}` : b;
  const options: ControlOptions = { store, artifactPath: join(dir, "artifacts"), evidencePath: join(dir, "evidence"), evidenceKey: "3".repeat(64),
    credentials: [{ tenantId: tenantA, token: admin, role: "admin" }, { tenantId: tenantA, token: operator, role: "operator" },
      { tenantId: tenantA, token: reader, role: "reader" }, { tenantId: tenantB, token: other, role: "admin" }] };
  let executions = 0;
  options.scanArtifact = async input => {
    executions++;
    const result = { artifactDigest: digest(input.artifactDir), toolSurfaceHash: surface, scanStatus: "PASSED", findings: [], scanId: input.scanId, source: "MOCK" };
    return { result, bundle: createEvidenceBundle({ "report.json": { ...result, scope: "STATIC_AI_SANDBOX" }, "sandbox/events.json": { mode: "DOCKER", complete: true },
      "sandbox/mcp.json": { complete: true }, "static/findings.json": [], "semantic/model-output.json": { findings: [] } }) };
  };
  const app = await buildApp({ adminApiToken: "synthetic-legacy-admin", scannerApiToken: "synthetic-legacy-scanner", controlPlane: options });
  for (const tenant of [tenantA, tenantB]) for (const item of [release("a"), release("c"), release("d", "npm:unrelated-fixture")]) await store.put(tenant, "release", item.releaseId, item);
  const request = (url: string, payload?: any, token = operator, key: string = randomUUID()) => app.inject({ method: payload === undefined ? "GET" : "POST", url,
    headers: { authorization: `Bearer ${token}`, "idempotency-key": key }, payload });
  const appeal = async (id = release("a").releaseId, token = operator, scanId?: string) => {
    const response = await request(`/v1/releases/${id}/appeals`, { reason: "Synthetic reason: review this immutable release", ...(scanId ? { scanId } : {}) }, token);
    assert.equal(response.statusCode, 201, response.body); return response.json().appeal;
  };
  const policy = async (document: any, token = admin) => {
    const response = await request("/v1/policies", { alias: "appeal-test-policy", document }, token);
    assert.equal(response.statusCode, 201, response.body); return response.json().policy.policyHash as string;
  };
  const history = async (id = release("a").releaseId, token = operator) => (await request(`/v1/releases/${id}/history`, undefined, token)).json().items;
  return { app, store, options, request, appeal, policy, history, tenantA, tenantB, executions: () => executions,
    close: async () => { await app.close(); await rm(dir, { recursive: true, force: true }); } };
}

test("UC-07/FR-406 fresh appeal scan bypasses a valid cached result and preserves original verdict/evidence/history", async () => {
  const f = await setup();
  try {
    const originalRelease = await f.store.get(a, "release", release("a").releaseId);
    const initial = (await f.request("/v1/scans", { releaseId: originalRelease!.releaseId, policyHash: hash(defaultPolicy) })).json().scan;
    await runControlWorkerOnce(f.store, f.options);
    const originalScan = await f.store.scan(a, initial.scanId);
    const originalEvidence = (await f.request(`/v1/scans/${initial.scanId}/evidence`)).json();
    const policyHash = await f.policy({ ...defaultPolicy, validitySeconds: 3600 });
    const body = { releaseId: originalRelease!.releaseId, policyHash };
    const cached = (await f.request("/v1/scans", body)).json().scan; await runControlWorkerOnce(f.store, f.options);
    assert.equal((await f.request("/v1/scans", body)).json().scan.scanId, cached.scanId);
    assert.equal(f.executions(), 2);
    const appeal = await f.appeal(originalRelease!.releaseId, operator, initial.scanId);
    assert.deepEqual(appeal.original, { artifactDigest: originalRelease!.artifactDigest, policyHash: hash(defaultPolicy), reportRoot: originalScan!.result!.reportRoot });
    const key = randomUUID(), payload = { ...body, appealId: appeal.appealId };
    const [first, second] = await Promise.all([f.request("/v1/scans", payload, operator, key), f.request("/v1/scans", payload, operator, key)]);
    assert.equal(first.statusCode, 202); assert.equal(second.statusCode, 202);
    assert.notEqual(first.json().scan.scanId, cached.scanId); assert.equal(second.json().scan.scanId, first.json().scan.scanId);
    assert.equal(first.json().reusedResult, false); assert.equal(first.json().scan.appealId, appeal.appealId);
    assert.equal((await f.request("/v1/scans", payload)).json().error.code, "APPEAL_RESCAN_ALREADY_REQUESTED");
    const resolution = { resolution: "Reviewed request; scan and quorum remain separate." };
    assert.equal((await f.request(`/v1/appeals/${appeal.appealId}/resolve`, resolution, admin)).statusCode, 200);
    await runControlWorkerOnce(f.store, f.options); assert.equal(f.executions(), 3);
    const completed = await f.store.scan(a, first.json().scan.scanId);
    assert.equal(completed?.status, "COMPLETED"); assert.notEqual(completed?.result?.reportRoot, originalScan?.result?.reportRoot);
    const storedAppeal = await f.store.get(a, "appeal", appeal.appealId);
    assert.equal(storedAppeal?.status, "RESOLVED"); assert.equal(storedAppeal?.rescan.scanId, completed?.scanId);
    assert.deepEqual(await f.store.get(a, "release", originalRelease!.releaseId), originalRelease);
    assert.deepEqual(await f.store.scan(a, initial.scanId), originalScan);
    assert.deepEqual((await f.request(`/v1/scans/${initial.scanId}/evidence`)).json(), originalEvidence);
    const events = await f.history();
    assert.equal(events.filter((event: any) => event.eventName === "appeal.rescan.queued").length, 1);
    assert.equal(events.filter((event: any) => event.eventName === "appeal.resolved").length, 1);
    assert.ok(events.some((event: any) => event.eventName === "appeal.rescan.completed" && event.payload.scanId === completed?.scanId && event.payload.reportRoot === completed.result?.reportRoot));
    assert.equal((await f.request("/v1/scans", payload, operator, key)).json().scan.scanId, completed?.scanId, "same request retry survives resolution");
    assert.doesNotMatch(JSON.stringify(events), /Synthetic reason|Reviewed request|evidenceKey|synthetic-appeal-operator-token/);
  } finally { await f.close(); }
});

test("appeals strictly enforce tenant ACL, changed digest/policy, profile, quota and immutable admin disposition", async () => {
  const f = await setup();
  try {
    const opened = await f.appeal(), payload = { releaseId: release("a").releaseId, policyHash: hash(defaultPolicy), appealId: opened.appealId };
    assert.equal((await f.request("/v1/scans", payload)).json().error.code, "APPEAL_NEW_DIGEST_OR_POLICY_REQUIRED");
    assert.equal((await f.request("/v1/scans", payload, reader)).statusCode, 403);
    assert.equal((await f.request("/v1/scans", payload, other)).statusCode, 404);
    assert.equal((await f.request("/v1/scans", { ...payload, releaseId: release("d", "npm:unrelated-fixture").releaseId })).json().error.code, "APPEAL_TOOL_MISMATCH");
    for (const bad of [{ ...payload, force: true }, { ...payload, appealId: "not-a-uuid" }, { ...payload, appealId: [opened.appealId] }, { ...payload, originalPolicyHash: hash(defaultPolicy) }]) assert.equal((await f.request("/v1/scans", bad)).statusCode, 400);
    assert.equal((await f.request("/v1/scans", { ...payload, policyHash: hash(preparedPolicy) })).json().error.code, "SCAN_PROFILE_MISMATCH");
    const expiredPolicy = await f.policy({ ...defaultPolicy, validitySeconds: 120 });
    await f.request(`/v1/policies/${expiredPolicy}/deprecate`, {}, admin);
    assert.equal((await f.request("/v1/scans", { ...payload, policyHash: expiredPolicy })).json().error.code, "POLICY_DEPRECATED");
    for (const [path, body] of [[`/v1/releases/${release("a").releaseId}/appeals`, { reason: "Synthetic reason", rescan: {} }],
      [`/v1/releases/${release("a").releaseId}/appeals`, { reason: "Synthetic reason", scanId: {} }],
      [`/v1/appeals/${opened.appealId}/resolve`, { resolution: "Synthetic conclusion", status: "VERIFIED" }]] as const) assert.equal((await f.request(path, body, admin)).statusCode, 400);
    const limited = await f.policy({ ...defaultPolicy, maxQueuedScans: 1 });
    await f.request("/v1/scans", { releaseId: release("c").releaseId, policyHash: limited });
    assert.equal((await f.request("/v1/scans", { ...payload, policyHash: limited })).statusCode, 429);
    assert.equal((await f.store.get(a, "appeal", opened.appealId))?.rescan, null);
    assert.equal((await f.request(`/v1/appeals/${opened.appealId}/resolve`, { resolution: "Synthetic conclusion one" })).statusCode, 403);
    assert.equal((await f.request(`/v1/appeals/${opened.appealId}/resolve`, { resolution: "Synthetic conclusion one" }, other)).statusCode, 404);
    const results = await Promise.all(["Synthetic conclusion one", "Synthetic conclusion two"].map(resolution => f.request(`/v1/appeals/${opened.appealId}/resolve`, { resolution }, admin)));
    assert.deepEqual(results.map(response => response.statusCode).sort(), [200, 409]);
    const accepted = results.find(response => response.statusCode === 200)!.json().appeal;
    const retry = await f.request(`/v1/appeals/${opened.appealId}/resolve`, { resolution: accepted.resolution }, admin);
    assert.equal(retry.json().deduplicated, true); assert.deepEqual(retry.json().appeal, accepted);
    assert.equal((await f.request("/v1/scans", { ...payload, releaseId: release("c").releaseId })).json().error.code, "APPEAL_NOT_OPEN");
    assert.equal((await f.history()).filter((event: any) => event.eventName === "appeal.resolved").length, 1);
    assert.equal((await f.store.get(a, "release", release("a").releaseId))?.status, "REVOKED");
    const legacyId = randomUUID();
    await f.store.put(a, "appeal", legacyId, { appealId: legacyId, releaseId: release("a").releaseId, status: "OPEN", scanId: null });
    assert.equal((await f.request("/v1/scans", { ...payload, appealId: legacyId, policyHash: limited })).json().error.code, "APPEAL_ORIGINAL_POLICY_REQUIRED");
  } finally { await f.close(); }
});

async function concurrentTenants(databaseUrl?: string) {
  const f = await setup(databaseUrl);
  try {
    const policy = { ...defaultPolicy, maxQueuedScans: 1 }, policyHash = await f.policy(policy); await f.policy(policy, other);
    const first = await f.appeal(), second = await f.appeal(), foreign = await f.appeal(release("a").releaseId, other);
    const submit = (appealId: string, token = operator) => f.request("/v1/scans", { releaseId: release("c").releaseId, policyHash, appealId }, token, "shared-key");
    const results = await Promise.all([submit(first.appealId), submit(first.appealId), submit(foreign.appealId, other)]);
    assert.ok(results.every(result => result.statusCode === 202));
    assert.equal(results[0].json().scan.scanId, results[1].json().scan.scanId);
    assert.notEqual(results[0].json().scan.scanId, results[2].json().scan.scanId);
    assert.equal((await f.request("/v1/scans", { releaseId: release("c").releaseId, policyHash, appealId: second.appealId })).statusCode, 429);
    assert.equal((await f.store.scanUsage(f.tenantA)).queued, 1); assert.equal((await f.store.scanUsage(f.tenantB)).queued, 1);
    f.options.scanArtifact = async () => { throw new Error("SYNTHETIC_PERMANENT_FAILURE"); };
    await Promise.all([runControlWorkerOnce(f.store, f.options), runControlWorkerOnce(f.store, f.options)]);
    for (const [token, tenantId, response] of [[operator, f.tenantA, results[0]], [other, f.tenantB, results[2]]] as const) {
      const history = await f.history(release("a").releaseId, token);
      const failed = history.filter((event: any) => event.eventName === "appeal.rescan.failed");
      assert.equal(failed.length, 1); assert.equal(failed[0].payload.scanId, response.json().scan.scanId);
      assert.equal((await f.store.scan(tenantId, failed[0].payload.scanId))?.status, "DEAD_LETTER");
      assert.equal((await f.store.get(tenantId, "release", release("a").releaseId))?.status, "REVOKED");
    }
    const dispositions = await Promise.all(["Synthetic native transaction conclusion A", "Synthetic native transaction conclusion B"].map(resolution => f.request(`/v1/appeals/${first.appealId}/resolve`, { resolution }, admin)));
    assert.deepEqual(dispositions.map(result => result.statusCode).sort(), [200, 409]);
    assert.equal((await f.history()).filter((event: any) => event.eventName === "appeal.resolved").length, 1);
  } finally { await f.close(); }
}
test("two tenants concurrently get one independent fresh job and failure history without crossing quota/idempotency", () => concurrentTenants());

async function workerLoss(databaseUrl?: string) {
  const f = await setup(databaseUrl);
  try {
    const original = await f.appeal(), foreign = await f.appeal(release("a").releaseId, other), live = await f.appeal();
    const submit = (appealId: string, token = operator) => f.request("/v1/scans", { releaseId: release("c").releaseId, policyHash: hash(defaultPolicy), appealId }, token);
    const responses = await Promise.all([submit(original.appealId), submit(foreign.appealId, other), submit(live.appealId)]);
    assert.ok(responses.every(response => response.statusCode === 202));
    const claims = await Promise.all(Array.from({ length: 3 }, () => f.store.claim(randomUUID(), 60000)));
    assert.equal(claims.filter(Boolean).length, 3);
    for (const response of responses.slice(0, 2)) await f.store.query("UPDATE cp_scans SET attempts=max_attempts,lease_expires_at=? WHERE scan_id=?",
      [new Date(Date.now() - 1).toISOString(), response.json().scan.scanId]);
    // A failing history insert must roll back the state/trigger event, not leave an unlinked terminal row.
    if (f.store.driver === "POSTGRESQL") {
      await f.store.query("CREATE FUNCTION test_appeal_loss_failure() RETURNS trigger AS $$ BEGIN IF NEW.event_name='appeal.rescan.failed' THEN RAISE EXCEPTION 'SYNTHETIC_AUDIT_FAILURE'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql");
      await f.store.query("CREATE TRIGGER test_appeal_loss_failure BEFORE INSERT ON cp_events FOR EACH ROW EXECUTE FUNCTION test_appeal_loss_failure()");
    } else await f.store.query("CREATE TRIGGER test_appeal_loss_failure BEFORE INSERT ON cp_events WHEN NEW.event_name='appeal.rescan.failed' BEGIN SELECT RAISE(ABORT,'SYNTHETIC_AUDIT_FAILURE'); END");
    await assert.rejects(f.store.claim(randomUUID()), /SYNTHETIC_AUDIT_FAILURE/);
    for (const [tenant, response] of [[f.tenantA, responses[0]], [f.tenantB, responses[1]]] as const) {
      assert.equal((await f.store.scan(tenant, response.json().scan.scanId))?.status, "RUNNING");
      assert.equal((await f.store.events(tenant, release("a").releaseId)).filter(event => event.eventName === "appeal.rescan.failed").length, 0);
    }
    await f.store.query(`DROP TRIGGER test_appeal_loss_failure${f.store.driver === "POSTGRESQL" ? " ON cp_events" : ""}`);
    if (f.store.driver === "POSTGRESQL") await f.store.query("DROP FUNCTION test_appeal_loss_failure()");
    const reaped = await Promise.all(Array.from({ length: 3 }, () => f.store.claim(randomUUID())));
    assert.ok(reaped.every(item => item === undefined));
    for (const [tenant, response] of [[f.tenantA, responses[0]], [f.tenantB, responses[1]]] as const) {
      const scanId = response.json().scan.scanId, current = await f.store.scan(tenant, scanId), stale = claims.find(item => item?.scanId === scanId)!;
      assert.equal(current?.status, "DEAD_LETTER"); assert.equal(current?.lastError?.code, "WORKER_LOST");
      assert.equal(current?.leaseOwner, undefined); assert.equal(current?.leaseExpiresAt, undefined);
      assert.equal(await f.store.finish(stale, stale.leaseOwner!, { verdict: "PASS" }), false);
      assert.equal(await f.store.fail(stale, stale.leaseOwner!, "STALE_FAILURE", false), false);
      const events = (await f.store.events(tenant, release("a").releaseId)).filter(event => event.eventName === "appeal.rescan.failed");
      assert.equal(events.length, 1); assert.equal(events[0].payload.scanId, scanId); assert.equal(events[0].payload.code, "WORKER_LOST");
      assert.equal(events[0].payload.retryable, true); assert.equal(events[0].payload.releaseId, release("c").releaseId);
      assert.equal((await f.store.events(tenant, release("c").releaseId)).filter(event => event.eventName === "scan.failed").length, 1);
      assert.equal((await f.store.get(tenant, "release", release("a").releaseId))?.status, "REVOKED");
    }
    const stillLive = await f.store.scan(f.tenantA, responses[2].json().scan.scanId);
    assert.equal(stillLive?.status, "RUNNING"); assert.equal(stillLive?.lastError, undefined);
  } finally { await f.close(); }
}
test("abrupt worker loss atomically records one terminal appeal failure per tenant and preserves live leases", () => workerLoss());

test("PostgreSQL appeal queue/link/history and disposition serialize with tenant-scoped native transactions", { skip: !process.env.MCPSHIELD_POSTGRES_TEST_URL }, async () => {
  const { Pool } = await import("pg"), pool = new Pool({ connectionString: process.env.MCPSHIELD_POSTGRES_TEST_URL });
  const schema = `mcpshield_appeal_${randomUUID().replace(/-/g, "")}`;
  assert.match(schema, /^mcpshield_appeal_[a-f0-9]{32}$/);
  try {
    // The queue claims globally by design: unrelated test suites must not consume one another's jobs.
    // Two tenants still run concurrently in the same real schema and connection pool here.
    await pool.query(`CREATE SCHEMA ${schema}`);
    const target = new URL(process.env.MCPSHIELD_POSTGRES_TEST_URL!); target.searchParams.set("options", `-csearch_path=${schema}`);
    await concurrentTenants(target.href);
    await workerLoss(target.href);
  } finally { await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); await pool.end(); }
});

test("appeal enqueue and link roll back together if the audit write fails", async () => {
  const f = await setup();
  try {
    const appeal = await f.appeal();
    await f.store.query("CREATE TRIGGER test_appeal_failure BEFORE INSERT ON cp_events WHEN NEW.event_name='appeal.rescan.queued' BEGIN SELECT RAISE(ABORT,'SYNTHETIC_AUDIT_FAILURE'); END");
    const payload = { releaseId: release("c").releaseId, policyHash: hash(defaultPolicy), appealId: appeal.appealId }, key = randomUUID();
    assert.ok((await f.request("/v1/scans", payload, operator, key)).statusCode >= 400);
    assert.equal((await f.store.scans(a)).length, 0); assert.equal((await f.store.get(a, "appeal", appeal.appealId))?.rescan, null);
    assert.equal((await f.history()).filter((event: any) => event.eventName.startsWith("appeal.rescan.")).length, 0);
    await f.store.query("DROP TRIGGER test_appeal_failure");
    assert.equal((await f.request("/v1/scans", payload, operator, key)).statusCode, 202);
  } finally { await f.close(); }
});

test("real local fixture resolver and static scanner perform an appeal rescan and persist new evidence without claiming Docker/PASS", async () => {
  const f = await setup();
  try {
    f.options.scanArtifact = undefined;
    const original = (await f.request("/v1/releases/resolve", { sourceType: "fixture", locator: "mail-mcp-1.0.0" })).json().release;
    const changed = (await f.request("/v1/releases/resolve", { sourceType: "fixture", locator: "mail-mcp-1.0.1" })).json().release;
    const appeal = await f.appeal(original.releaseId), payload = { releaseId: changed.releaseId, policyHash: hash(defaultPolicy), appealId: appeal.appealId, baselineReleaseId: original.releaseId };
    const queued = await f.request("/v1/scans", payload); assert.equal(queued.statusCode, 202, queued.body);
    await runControlWorkerOnce(f.store, f.options);
    const completed = (await f.request(`/v1/scans/${queued.json().scan.scanId}`)).json().scan;
    assert.equal(completed.status, "COMPLETED"); assert.equal(completed.result.verdict, "FAIL", "static deterministic findings can deny, but no Docker observation or PASS is fabricated");
    const evidence = await f.request(`/v1/scans/${completed.scanId}/evidence`);
    assert.equal(evidence.statusCode, 200); assert.equal(evidence.json().reportRoot, completed.result.reportRoot);
    assert.ok((await f.history(original.releaseId)).some((event: any) => event.eventName === "appeal.rescan.completed" && event.payload.releaseId === changed.releaseId));
    assert.equal((await f.request(`/v1/releases/${original.releaseId}`)).json().release.status, "UNVERIFIED");
    assert.equal((await f.request(`/v1/releases/${changed.releaseId}`)).json().release.status, "UNVERIFIED");
  } finally { await f.close(); }
});
