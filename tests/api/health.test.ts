import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { buildApp } from "../../apps/api/src/app.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import type { ControlOptions } from "../../apps/api/src/control-plane.js";
import { createControlHealth } from "../../apps/api/src/control-health.js";
import { HEARTBEAT_KIND, HEARTBEAT_TTL_MS, probeScannerDocker, scannerHealth, startScannerHeartbeat } from "../../apps/api/src/worker-health.js";
import { privateNode } from "./runtime-fullcycle-helpers.js";

const tenantId = "health-test", credentials = ["admin", "operator", "reader"].map(role => ({ tenantId, role: role as "admin" | "operator" | "reader", token: `synthetic-health-${role}-token` }));
const chain = (health = async () => ({ status: "UP" as const, code: "CHAIN_READY" })) => Object.assign(async () => ({ status: "UNVERIFIED" }), { health });
function heartbeat(time = Date.now(), change: Record<string, any> = {}) {
  const updatedAt = new Date(time).toISOString();
  return { schemaVersion: "mcpshield.scanner-heartbeat.v1", mode: "SCAN", state: "RUNNING", sandbox: "DOCKER",
    probe: { status: "UP", code: "DOCKER_AVAILABLE", checkedAt: updatedAt }, updatedAt, ...change };
}
const row = (document: any) => ({ document: JSON.stringify(document), created_at: document.updatedAt });
async function setup(extra: Partial<ControlOptions> = {}) {
  const store = await ControlStore.open(), options: ControlOptions = { store, credentials: [...credentials, { tenantId: "foreign-health", role: "reader", token: "synthetic-foreign-health-token" }],
    artifactPath: "unused", evidencePath: "unused", evidenceKey: "1".repeat(64), ...extra };
  const app = await buildApp({ adminApiToken: "synthetic-legacy-admin", scannerApiToken: "synthetic-legacy-scanner", controlPlane: options });
  const request = (token = credentials[0].token) => app.inject({ url: "/v1/health", headers: { authorization: `Bearer ${token}` } });
  return { app, store, options, request };
}

test("composite readiness is authenticated, tenant-bound and additive to unchanged public liveness", async () => {
  const f = await setup({ chainDecision: chain() });
  try {
    const document = heartbeat(); await f.store.put(tenantId, HEARTBEAT_KIND, "synthetic-worker", document);
    // put() stamps created_at itself; pin the exact persisted observation as the real writer does.
    await f.store.query("UPDATE cp_records SET created_at=? WHERE tenant_id=? AND kind=?", [document.updatedAt, tenantId, HEARTBEAT_KIND]);
    assert.equal((await f.request("invalid")).statusCode, 401);
    assert.equal((await f.app.inject({ url: "/v1/health" })).statusCode, 401);
    for (const { token } of credentials) {
      const response = await f.request(token), body = response.json();
      assert.equal(response.statusCode, 200); assert.equal(response.headers["cache-control"], "no-store");
      assert.equal(body.schemaVersion, "mcpshield.health.v1"); assert.equal(body.status, "READY");
      assert.deepEqual(Object.keys(body.components).sort(), ["api", "chain", "database", "scanner"]);
      for (const value of Object.values(body.components) as any[]) {
        assert.deepEqual(Object.keys(value).sort(), ["checkedAt", "code", "status"]); assert.equal(value.status, "UP");
        assert.ok(Number.isFinite(Date.parse(value.checkedAt)));
      }
      assert.doesNotMatch(response.body, /synthetic-worker|synthetic-health|foreign-health|http|credential|hostname/);
    }
    const foreign = await f.request("synthetic-foreign-health-token"); assert.equal(foreign.statusCode, 503);
    assert.equal(foreign.json().components.scanner.code, "SCANNER_HEARTBEAT_MISSING");
    const legacy = await f.app.inject({ url: "/health" }); assert.equal(legacy.statusCode, 200);
    assert.deepEqual(legacy.json(), { schemaVersion: "1.0.0", status: "ok", ledgerMode: "LOCAL_DEMO" });
  } finally { await f.app.close(); }
});

test("no configuration or heartbeat never becomes ready, and configured chain without a probe remains unknown", async () => {
  for (const reader of [undefined, async () => ({ status: "VERIFIED" })]) {
    const f = await setup({ chainDecision: reader });
    try {
      const response = await f.request(); assert.equal(response.statusCode, 503); const health = response.json();
      assert.equal(health.components.database.status, "UP"); assert.equal(health.components.scanner.status, "UNKNOWN");
      assert.equal(health.components.chain.status, reader ? "UNKNOWN" : "NOT_CONFIGURED");
    } finally { await f.app.close(); }
  }
});

test("scanner observations reject malformed, future, expired and chain-only records without masking another live worker", () => {
  const now = Date.now(), valid = heartbeat(now - 1000);
  for (const [document, code] of [
    [heartbeat(now - HEARTBEAT_TTL_MS - 1), "SCANNER_HEARTBEAT_STALE"], [heartbeat(now + 1), "SCANNER_CLOCK_INVALID"],
    [{ ...valid, updatedAt: "invalid" }, "SCANNER_HEARTBEAT_INVALID"], [{ ...valid, mode: "CHAIN_ONLY" }, "SCANNER_HEARTBEAT_INVALID"],
    [{ ...valid, secret: "SYNTHETIC_PRIVATE_DATA" }, "SCANNER_HEARTBEAT_INVALID"], [{ ...valid, probe: { status: "UP", code: "FAKE_DOCKER", checkedAt: valid.updatedAt } }, "SCANNER_HEARTBEAT_INVALID"],
  ] as const) {
    assert.equal(scannerHealth([row(document)], now).code, code);
    assert.equal(scannerHealth([row(document), row(valid)], now).status, "UP");
  }
  assert.equal(scannerHealth([{ document: "{malformed", created_at: valid.updatedAt }], now).status, "UNKNOWN");
  assert.equal(scannerHealth([{ ...row(valid), created_at: new Date(now).toISOString() }], now).status, "UNKNOWN");
  const stopped = heartbeat(now - 1000, { state: "STOPPED", probe: { status: "DOWN", code: "WORKER_STOPPED", checkedAt: valid.updatedAt } });
  assert.equal(scannerHealth([row(stopped)], now).code, "SCANNER_STOPPED");
  assert.equal(scannerHealth([row(stopped), row(valid)], now).status, "UP");
  assert.equal(scannerHealth(Array.from({ length: 65 }, () => row(stopped)), now).code, "SCANNER_INVENTORY_TRUNCATED");
});

test("database failure and chain failure are sanitized degraded components, not liveness failures", async context => {
  const f = await setup({ chainDecision: chain(async () => { throw Error("https://private.invalid/?token=SYNTHETIC_PRIVATE_DATA"); }) });
  try {
    context.mock.method(f.store, "query", async () => { throw Error("SYNTHETIC_PRIVATE_DATABASE_CREDENTIAL"); });
    const response = await f.request(); assert.equal(response.statusCode, 503);
    const { components } = response.json(); assert.equal(components.api.status, "UP"); assert.equal(components.database.code, "DATABASE_UNAVAILABLE");
    assert.equal(components.scanner.code, "SCANNER_DATABASE_UNAVAILABLE"); assert.equal(components.chain.code, "CHAIN_PROBE_FAILED");
    assert.doesNotMatch(response.body, /private|SYNTHETIC|credential|http/);
  } finally { await f.app.close(); }
});

test("bounded health probes coalesce requests and retain timed-out pending work until settlement", async context => {
  let chainCalls = 0, dbCalls = 0, releaseDb!: (value: any[]) => void, releaseChain!: (value: { status: "UP"; code: string }) => void;
  const f = await setup({ chainDecision: chain(() => { chainCalls++; return new Promise(resolve => { releaseChain = resolve; }); }) });
  try {
    context.mock.method(f.store, "query", async () => { dbCalls++; return new Promise<any[]>(resolve => { releaseDb = resolve; }); });
    const started = Date.now(), responses = await Promise.all(Array.from({ length: 24 }, () => f.request()));
    assert.ok(Date.now() - started < 4000); assert.equal(dbCalls, 1); assert.equal(chainCalls, 1);
    for (const response of responses) {
      assert.equal(response.statusCode, 503); assert.equal(response.json().components.database.code, "DATABASE_TIMEOUT");
      assert.equal(response.json().components.chain.code, "CHAIN_PROBE_TIMEOUT");
    }
    await Promise.all(Array.from({ length: 12 }, () => f.request())); assert.equal(dbCalls, 1); assert.equal(chainCalls, 1);
  } finally { releaseDb?.([]); releaseChain?.({ status: "UP", code: "CHAIN_READY" }); await f.app.close(); }
});

test("cached observations preserve their timestamps but expired scanner evidence is re-evaluated on each read", async () => {
  const store = await ControlStore.open();
  try {
    const document = heartbeat(Date.now() - HEARTBEAT_TTL_MS + 150);
    await store.put(tenantId, HEARTBEAT_KIND, "synthetic-worker", document);
    await store.query("UPDATE cp_records SET created_at=? WHERE tenant_id=? AND kind=?", [document.updatedAt, tenantId, HEARTBEAT_KIND]);
    const read = createControlHealth(store, { credentials, artifactPath: "unused", evidencePath: "unused", evidenceKey: "1".repeat(64), chainDecision: chain() });
    const first = await read(tenantId); assert.equal(first.components.scanner.status, "UP");
    await new Promise(resolve => setTimeout(resolve, 180));
    const second = await read(tenantId); assert.equal(second.components.scanner.code, "SCANNER_HEARTBEAT_STALE");
    assert.equal(second.components.scanner.checkedAt, first.components.scanner.checkedAt);
    assert.equal(second.components.database.checkedAt, first.components.database.checkedAt);
    assert.equal(second.components.chain.checkedAt, first.components.chain.checkedAt);
  } finally { await store.close(); }
});

test("actual SQL heartbeat lifecycle isolates tenant roles and modes; Docker readiness here is explicitly synthetic", async () => {
  const f = await setup({ scannerOptions: { sandbox: "docker", allowRemoteAi: false }, chainDecision: chain() });
  let probes = 0;
  const first = startScannerHeartbeat(f.store, f.options, "SCAN", async () => { probes++; return { status: "UP", code: "DOCKER_AVAILABLE" }; });
  const second = startScannerHeartbeat(f.store, f.options, "ALL", async () => ({ status: "UP", code: "DOCKER_AVAILABLE" }));
  const chainOnly = startScannerHeartbeat(f.store, f.options, "CHAIN_ONLY", async () => { assert.fail("chain-only must never probe scanner"); });
  try {
    await Promise.all([first.pulse(), second.pulse(), chainOnly.pulse()]); assert.equal(probes, 1);
    assert.equal((await f.store.list(tenantId, HEARTBEAT_KIND)).length, 2); assert.equal((await f.store.list("foreign-health", HEARTBEAT_KIND)).length, 0);
    const rows = () => f.store.query("SELECT document,created_at FROM cp_records WHERE tenant_id=? AND kind=?", [tenantId, HEARTBEAT_KIND]);
    assert.equal(scannerHealth(await rows()).status, "UP");
    await first.stop(); assert.equal(scannerHealth(await rows()).status, "UP");
    await second.stop(); assert.equal(scannerHealth(await rows()).code, "SCANNER_STOPPED");
    const staticWorker = startScannerHeartbeat(f.store, { ...f.options, scannerOptions: undefined }, "SCAN", async () => { assert.fail("static mode cannot probe or claim Docker"); });
    try { await staticWorker.pulse(); assert.equal(scannerHealth(await rows()).code, "SCANNER_STATIC_ONLY"); }
    finally { await staticWorker.stop(); }
  } finally { await Promise.all([first.stop(), second.stop(), chainOnly.stop()]); await f.app.close(); }
});

test("actual worker CLI persists STOPPED heartbeat on --once and chain-only mode never advertises a scanner", async () => {
  const dir = await mkdtemp(join(tmpdir(), "mcpshield-health-cli-"));
  try {
    for (const mode of ["--scan-only", "--chain-only"]) {
      const result = await privateNode(`
        let text = ''; for await (const chunk of process.stdin) text += chunk;
        const config = JSON.parse(text);
        Object.assign(process.env, { CONTROL_PLANE_ENABLED: 'true', CONTROL_PLANE_CREDENTIALS: JSON.stringify(config.credentials), CONTROL_DATABASE_URL: config.database,
          CONTROL_EVIDENCE_KEY: '1'.repeat(64), CONTROL_ALLOW_REMOTE_AI: 'false' });
        process.argv.push('--once', config.mode);
        await import(${JSON.stringify(new URL("../../apps/api/src/control-worker-cli.ts", import.meta.url).href)});
        const { ControlStore } = await import(${JSON.stringify(new URL("../../apps/api/src/control-store.ts", import.meta.url).href)});
        const store = await ControlStore.open(config.database);
        const rows = await store.query("SELECT document FROM cp_records WHERE kind='scannerHeartbeat'"); await store.close();
        process.stdout.write(JSON.stringify(rows.map(row => JSON.parse(row.document))));
      `, { database: join(dir, `${mode.slice(2)}.sqlite`), credentials, mode }, 10000);
      if (mode === "--chain-only") assert.deepEqual(result, []);
      else { assert.equal(result.length, 1); assert.equal(result[0].state, "STOPPED"); assert.equal(result[0].sandbox, "STATIC_ONLY"); }
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("PostgreSQL heartbeat writes are visible across actual worker/API connections", { skip: !process.env.MCPSHIELD_POSTGRES_TEST_URL }, async () => {
  const tenant = `health-${randomUUID()}`, one = await ControlStore.open(process.env.MCPSHIELD_POSTGRES_TEST_URL), two = await ControlStore.open(process.env.MCPSHIELD_POSTGRES_TEST_URL);
  const options = { credentials: [{ ...credentials[1], tenantId: tenant }], artifactPath: "unused", evidencePath: "unused", evidenceKey: "1".repeat(64) };
  const worker = startScannerHeartbeat(one, options, "SCAN");
  try {
    await worker.pulse(); const read = createControlHealth(two, options);
    assert.equal((await read(tenant)).components.scanner.status, "LIMITED");
    await worker.stop();
    assert.equal(scannerHealth(await two.query("SELECT document,created_at FROM cp_records WHERE tenant_id=? AND kind=?", [tenant, HEARTBEAT_KIND])).code, "SCANNER_STOPPED");
  } finally { await worker.stop(); await one.query("DELETE FROM cp_records WHERE tenant_id=? AND kind=?", [tenant, HEARTBEAT_KIND]); await Promise.all([one.close(), two.close()]); }
});

test("native Linux Docker availability probe reports the actual daemon, not configured flags", { skip: process.env.MCPSHIELD_DOCKER_TESTS !== "1" }, async () => {
  assert.deepEqual(await probeScannerDocker(), { status: "UP", code: "DOCKER_AVAILABLE" });
});

test("health-specific SQLite lock timeout is bounded and restored for ordinary queries", async () => {
  const store = await ControlStore.open();
  try {
    assert.equal((await store.query("PRAGMA busy_timeout", [], 100))[0].timeout, 100);
    assert.equal((await store.query("PRAGMA busy_timeout"))[0].timeout, 5000);
    await assert.rejects(store.query("SELECT * FROM missing_health_table", [], 100));
    assert.equal((await store.query("PRAGMA busy_timeout"))[0].timeout, 5000);
    await assert.rejects(store.query("SELECT 1", [], -1), /INVALID_SQLITE_BUSY_TIMEOUT/);
  } finally { await store.close(); }
});
