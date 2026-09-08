import { DatabaseSync } from "node:sqlite";
import { readFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { setTimeout as pause } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import type { Pool, PoolClient } from "pg";

export interface ScanJob {
  scanId: string; tenantId: string; releaseId: string; policyHash: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "DEAD_LETTER";
  stage: string; attempts: number; maxAttempts: number; traceId: string;
  createdAt: string; updatedAt: string; nextAttemptAt: string;
  leaseOwner?: string; leaseExpiresAt?: string; lastError?: { code: string; retryable: boolean };
  request: Record<string, any>; result?: Record<string, any>;
}
const job = (row: Record<string, any>): ScanJob => ({
  scanId: row.scan_id, tenantId: row.tenant_id, releaseId: row.release_id, policyHash: row.policy_hash,
  status: row.state, stage: row.stage, attempts: row.attempts, maxAttempts: row.max_attempts,
  traceId: row.trace_id, createdAt: row.created_at, updatedAt: row.updated_at, nextAttemptAt: row.next_attempt_at,
  leaseOwner: row.lease_owner ?? undefined, leaseExpiresAt: row.lease_expires_at ?? undefined,
  lastError: row.last_error ? JSON.parse(row.last_error) : undefined,
  request: JSON.parse(row.request_json), result: row.result_json ? JSON.parse(row.result_json) : undefined,
});

export class ControlStore {
  private sqlite?: DatabaseSync;
  private pool?: Pool;
  private transactionClient?: PoolClient;
  private sqliteTransaction = Promise.resolve();
  private constructor() {}
  static async open(location = ":memory:") {
    const store = new ControlStore();
    if (/^postgres(?:ql)?:\/\//.test(location)) {
      const { Pool } = await import("pg");
      store.pool = new Pool({ connectionString: location, max: 10, connectionTimeoutMillis: 5000, statement_timeout: 10000 });
    } else {
      if (location !== ":memory:") mkdirSync(dirname(resolve(location)), { recursive: true });
      store.sqlite = new DatabaseSync(location);
      store.sqlite.exec("PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
    }
    const migration = (name: string) => readFileSync(fileURLToPath(new URL(`../../../database/migrations/${name}.sql`, import.meta.url)), "utf8");
    const names = ["002_control_plane", `003_scan_audit.${store.pool ? "pg" : "sqlite"}`, "004_chain_outbox", "006_scan_request_keys", "007_receipt_anchors", `009_scan_trace_index.${store.pool ? "pg" : "sqlite"}`, "010_runtime_preparations"];
    const schema = names.map(migration).join("\n");
    const extensions = [
      { name: "005_chain_action_domain", column: "registry_address", sql: migration("005_chain_action_domain") },
      { name: "008_submission_trace", column: "submission_trace_parent", sql: migration("008_submission_trace") },
    ];
    if (store.sqlite) {
      store.sqlite.exec("BEGIN IMMEDIATE");
      try {
        store.sqlite.exec(schema);
        const columns = store.sqlite.prepare("PRAGMA table_info(cp_chain_actions)").all();
        for (const extension of extensions) if (!columns.some((column) => column.name === extension.column)) store.sqlite.exec(extension.sql);
        store.sqlite.exec("COMMIT");
      } catch (error) { store.sqlite.exec("ROLLBACK"); store.sqlite.close(); throw error; }
    } else {
      try {
        const client = await store.pool!.connect();
        let destroyed = false;
        // Evicting this one connection aborts any outstanding SQL and rolls its transaction back server-side.
        const totalDeadline = setTimeout(() => { destroyed = true; client.release(true); }, 15000);
        try {
          const plan = [...names.map((name) => ({ name, sql: migration(name), column: undefined as string | undefined })), ...extensions].sort((a, b) => a.name.localeCompare(b.name));
          const deadline = Date.now() + 15000;
          for (let attempt = 0; ; attempt++) {
            try {
              await client.query("BEGIN");
              const remaining = Math.max(1, deadline - Date.now());
              await client.query("SELECT set_config('statement_timeout',$1,true)", [`${remaining}ms`]);
              await client.query("SELECT pg_advisory_xact_lock(hashtext('mcpshield-control-migrations'))");
              await client.query("CREATE TABLE IF NOT EXISTS cp_schema_migrations (migration_id TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)");
              const applied = new Map((await client.query("SELECT migration_id,checksum FROM cp_schema_migrations")).rows.map((row) => [row.migration_id, row.checksum]));
              for (const step of plan) {
                if (Date.now() >= deadline) throw Error("CONTROL_MIGRATION_DEADLINE");
                await client.query("SELECT set_config('statement_timeout',$1,true)", [`${Math.max(1, deadline - Date.now())}ms`]);
                const checksum = createHash("sha256").update(step.sql.replace(/\r\n/g, "\n")).digest("hex"), previous = applied.get(step.name);
                if (previous && previous !== checksum) throw Error("CONTROL_MIGRATION_CHECKSUM_MISMATCH");
                if (previous) continue;
                const columns = step.column ? (await client.query("SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='cp_chain_actions'")).rows : [];
                if (!step.column || !columns.some((column) => column.column_name === step.column)) await client.query(step.sql);
                await client.query("INSERT INTO cp_schema_migrations(migration_id,checksum,applied_at) VALUES($1,$2,$3)", [step.name, checksum, new Date().toISOString()]);
              }
              await client.query("COMMIT"); break;
            } catch (error: any) {
              if (destroyed) throw Error("CONTROL_MIGRATION_DEADLINE");
              await client.query("ROLLBACK").catch(() => {});
              // Only first-upgrade DDL can still meet existing business transactions. Retry the whole atomic migration, never hide other errors.
              if (error?.code !== "40P01" || attempt >= 2 || Date.now() + 50 * (attempt + 1) >= deadline) throw error;
              await pause(50 * (attempt + 1));
            }
          }
        } finally { clearTimeout(totalDeadline); if (!destroyed) client.release(); }
      } catch (error) { await store.pool!.end().catch(() => {}); throw error; }
    }
    return store;
  }
  get driver() { return this.pool ? "POSTGRESQL" : "SQLITE"; }
  async close() { if (this.pool) await this.pool.end(); else this.sqlite?.close(); }
  async query(sql: string, values: Array<string | number | null> = []): Promise<Record<string, any>[]> {
    if (this.pool) { let index = 0; return (await (this.transactionClient ?? this.pool).query(sql.replace(/\?/g, () => `$${++index}`), values)).rows; }
    await this.sqliteTransaction;
    return this.sqlite!.prepare(sql).all(...values) as Record<string, any>[];
  }
  async forTenant<T>(tenantId: string, execute: (transaction: ControlStore) => Promise<T>): Promise<T> {
    if (this.pool) {
      const transaction = new ControlStore(), client = await this.pool.connect();
      transaction.pool = this.pool; transaction.transactionClient = client;
      try {
        await client.query("BEGIN");
        await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [tenantId]);
        const result = await execute(transaction); await client.query("COMMIT"); return result;
      } catch (error) { await client.query("ROLLBACK"); throw error; }
      finally { client.release(); }
    }
    // One SQLite connection cannot interleave transactions. PostgreSQL locks only the relevant tenant.
    const previous = this.sqliteTransaction; let unlock!: () => void;
    this.sqliteTransaction = new Promise<void>((resolve) => { unlock = resolve; }); await previous;
    try {
      this.sqlite!.exec("BEGIN IMMEDIATE");
      const transaction = new ControlStore(); transaction.sqlite = this.sqlite;
      try { const result = await execute(transaction); this.sqlite!.exec("COMMIT"); return result; }
      catch (error) { this.sqlite!.exec("ROLLBACK"); throw error; }
    } finally { unlock(); }
  }
  async put(tenantId: string, kind: string, id: string, document: Record<string, any>, replace = false) {
    const conflict = replace ? "DO UPDATE SET document = excluded.document" : "DO NOTHING";
    const rows = await this.query(`INSERT INTO cp_records (tenant_id, kind, id, document, created_at) VALUES (?, ?, ?, ?, ?)
      ON CONFLICT (tenant_id, kind, id) ${conflict} RETURNING id`, [tenantId, kind, id, JSON.stringify(document), new Date().toISOString()]);
    return rows.length === 1;
  }
  async get(tenantId: string, kind: string, id: string): Promise<Record<string, any> | undefined> {
    const [row] = await this.query("SELECT document FROM cp_records WHERE tenant_id = ? AND kind = ? AND id = ?", [tenantId, kind, id]);
    return row ? JSON.parse(row.document) : undefined;
  }
  async list(tenantId: string, kind: string) {
    return (await this.query("SELECT document FROM cp_records WHERE tenant_id = ? AND kind = ? ORDER BY created_at DESC LIMIT 250", [tenantId, kind])).map((row) => JSON.parse(row.document));
  }
  async event(tenantId: string, releaseId: string | null, eventName: string, payload: Record<string, any>, traceId: string = randomUUID()) {
    const eventId = randomUUID();
    await this.query("INSERT INTO cp_events (event_id, tenant_id, release_id, event_name, payload, trace_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [eventId, tenantId, releaseId, eventName, JSON.stringify(payload), traceId, new Date().toISOString()]);
    return eventId;
  }
  async events(tenantId: string, releaseId?: string) {
    const rows = await this.query(`SELECT * FROM cp_events WHERE tenant_id = ?${releaseId ? " AND release_id = ?" : ""} ORDER BY created_at DESC, event_id LIMIT 250`, [tenantId, ...(releaseId ? [releaseId] : [])]);
    return rows.map((row) => ({ eventId: row.event_id, tenantId: row.tenant_id, releaseId: row.release_id,
      eventName: row.event_name, payload: JSON.parse(row.payload), traceId: row.trace_id, createdAt: row.created_at }));
  }
  async enqueue(tenantId: string, request: Record<string, any>, idempotencyKey: string, requestHash: string, traceId: string) {
    const now = new Date().toISOString();
    const scanId = randomUUID();
    const inserted = await this.query(`INSERT INTO cp_scans (scan_id, tenant_id, release_id, policy_hash, idempotency_key, request_hash,
      request_json, state, stage, max_attempts, next_attempt_at, trace_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'QUEUED', 'PENDING', 3, ?, ?, ?, ?)
      ON CONFLICT (tenant_id, idempotency_key) DO NOTHING RETURNING scan_id`,
      [scanId, tenantId, request.releaseId, request.policyHash, idempotencyKey, requestHash, JSON.stringify(request), now, traceId, now, now]);
    const [row] = await this.query("SELECT * FROM cp_scans WHERE tenant_id = ? AND idempotency_key = ?", [tenantId, idempotencyKey]);
    if (row.request_hash !== requestHash) throw new Error("IDEMPOTENCY_CONFLICT");
    return { scan: job(row), deduplicated: !inserted.length };
  }
  async scan(tenantId: string, scanId: string) {
    const [row] = await this.query("SELECT * FROM cp_scans WHERE tenant_id = ? AND scan_id = ?", [tenantId, scanId]);
    return row ? job(row) : undefined;
  }
  async scanTraceContext(tenantId: string, releaseId: string, policyHash: string, reportRoot: string) {
    const field = this.pool ? "result_json::jsonb->>'reportRoot'" : "json_extract(result_json, '$.reportRoot')";
    const [row] = await this.query(`SELECT scan_id,trace_id,request_json FROM cp_scans WHERE tenant_id = ? AND release_id = ? AND policy_hash = ?
      AND state = 'COMPLETED' AND ${field} = ? ORDER BY updated_at DESC,scan_id LIMIT 1`, [tenantId, releaseId, policyHash, reportRoot]);
    if (!row) return undefined;
    const traceparent = JSON.parse(row.request_json).traceparent;
    if (typeof traceparent !== "string" || !/^00-(?!0{32})[0-9a-f]{32}-(?!0{16})[0-9a-f]{16}-0[01]$/.test(traceparent) || traceparent.split("-")[1] !== row.trace_id) return undefined;
    return { scanId: row.scan_id as string, traceparent };
  }
  async idempotentScan(tenantId: string, key: string, requestHash: string) {
    const [alias] = await this.query("SELECT scan_id,request_hash FROM cp_scan_request_keys WHERE tenant_id = ? AND idempotency_key = ?", [tenantId, key]);
    if (alias) {
      if (alias.request_hash !== requestHash) throw Object.assign(new Error("IDEMPOTENCY_CONFLICT"), { statusCode: 409 });
      return this.scan(tenantId, alias.scan_id);
    }
    const [row] = await this.query("SELECT * FROM cp_scans WHERE tenant_id = ? AND idempotency_key = ?", [tenantId, key]);
    if (row && row.request_hash !== requestHash) throw Object.assign(new Error("IDEMPOTENCY_CONFLICT"), { statusCode: 409 });
    return row ? job(row) : undefined;
  }
  async enqueueConstrained(tenantId: string, request: Record<string, any>, key: string, requestHash: string, traceId: string,
    release: Record<string, any>, policy: Record<string, any>) {
    return this.forTenant(tenantId, async (transaction) => {
      const existing = await transaction.idempotentScan(tenantId, key, requestHash);
      if (existing) return { scan: existing, deduplicated: true, reusedResult: false };
      const field = (column: string, name: string) => this.pool ? `${column}::jsonb->>'${name}'` : `json_extract(${column}, '$.${name}')`;
      const now = new Date().toISOString();
      const [cached] = await transaction.query(`SELECT * FROM cp_scans WHERE tenant_id = ? AND release_id = ? AND policy_hash = ?
        AND state = 'COMPLETED' AND ${field("result_json", "validUntil")} > ? AND ${field("result_json", "verdict")} IN ('PASS','FAIL')
        ${request.baselineReleaseId ? `AND ${field("request_json", "baselineReleaseId")} = ?` : ""} ORDER BY updated_at DESC LIMIT 1`,
        [tenantId, request.releaseId, request.policyHash, now, ...(request.baselineReleaseId ? [request.baselineReleaseId] : [])]);
      let result;
      if (cached) result = { scan: job(cached), deduplicated: true, reusedResult: true };
      else {
        const usage = await transaction.scanUsage(tenantId);
        if (usage.today >= policy.maxDailyScans || usage.queued >= policy.maxQueuedScans) throw Object.assign(new Error("SCAN_QUOTA_EXCEEDED"), { statusCode: 429 });
        let baselineReleaseId = request.baselineReleaseId;
        if (!baselineReleaseId && !release.runtimeProfile) {
          const [baseline] = await transaction.query(`SELECT id FROM cp_records WHERE tenant_id = ? AND kind = 'release' AND id <> ?
            AND ${field("document", "toolId")} = ? AND ${field("document", "status")} = 'VERIFIED' AND ${field("document", "runtimeProfile")} IS NULL
            AND ${field("document", "validUntil")} > ? AND created_at <= ? ORDER BY created_at DESC LIMIT 1`,
            [tenantId, request.releaseId, release.toolId, now, release.createdAt ?? now]);
          baselineReleaseId = baseline?.id;
        }
        result = { ...await transaction.enqueue(tenantId, { ...request, ...(baselineReleaseId ? { baselineReleaseId } : {}) }, key, requestHash, traceId), reusedResult: false };
      }
      await transaction.query("INSERT INTO cp_scan_request_keys(tenant_id,idempotency_key,request_hash,scan_id) VALUES(?,?,?,?)", [tenantId, key, requestHash, result.scan.scanId]);
      return result;
    });
  }
  async scanUsage(tenantId: string) {
    const counts: Record<string, number> = { QUEUED: 0, RUNNING: 0, COMPLETED: 0, DEAD_LETTER: 0 };
    for (const row of await this.query("SELECT state, COUNT(*) AS count FROM cp_scans WHERE tenant_id = ? GROUP BY state", [tenantId])) counts[row.state] = Number(row.count);
    const [daily] = await this.query("SELECT COUNT(*) AS count FROM cp_scans WHERE tenant_id = ? AND created_at >= ?", [tenantId, new Date().toISOString().slice(0, 10)]);
    // A successful preparation produces one cp_scans row. Count only preparations without that child again.
    const resultScan = this.pool ? "result_json::jsonb->>'scanId'" : "json_extract(result_json, '$.scanId')";
    const [preparations] = await this.query(`SELECT COUNT(*) AS count FROM cp_preparations WHERE tenant_id = ? AND created_at >= ? AND ${resultScan} IS NULL`, [tenantId, new Date().toISOString().slice(0, 10)]);
    const [pending] = await this.query("SELECT COUNT(*) AS count FROM cp_preparations WHERE tenant_id = ? AND state IN ('QUEUED','RUNNING')", [tenantId]);
    return { counts, today: Number(daily.count) + Number(preparations.count), queued: counts.QUEUED + counts.RUNNING + Number(pending.count) };
  }
  async scans(tenantId: string) { return (await this.query("SELECT * FROM cp_scans WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 250", [tenantId])).map(job); }
  async claim(owner: string, leaseMs = 180000) {
    const now = new Date().toISOString();
    await this.query(`UPDATE cp_scans SET state = 'DEAD_LETTER', last_error = ?, updated_at = ?
      WHERE state = 'RUNNING' AND lease_expires_at <= ? AND attempts >= max_attempts`,
      [JSON.stringify({ code: "WORKER_LOST", retryable: true }), now, now]);
    // A single UPDATE + RETURNING is the durable queue: no DB/queue dual write.
    const rows = await this.query(`UPDATE cp_scans SET state = 'RUNNING', stage = 'SCANNING', attempts = attempts + 1,
      lease_owner = ?, lease_expires_at = ?, updated_at = ? WHERE scan_id = (
        SELECT scan_id FROM cp_scans WHERE attempts < max_attempts AND ((state = 'QUEUED' AND next_attempt_at <= ?)
          OR (state = 'RUNNING' AND lease_expires_at <= ?)) ORDER BY created_at LIMIT 1${this.pool ? " FOR UPDATE SKIP LOCKED" : ""})
      RETURNING *`, [owner, new Date(Date.now() + leaseMs).toISOString(), now, now, now]);
    return rows[0] ? job(rows[0]) : undefined;
  }
  async finish(scan: ScanJob, owner: string, result: Record<string, any>) {
    return (await this.query(`UPDATE cp_scans SET state = 'COMPLETED', stage = 'DONE', result_json = ?, lease_owner = NULL,
      lease_expires_at = NULL, updated_at = ? WHERE scan_id = ? AND state = 'RUNNING' AND lease_owner = ? AND lease_expires_at > ? RETURNING scan_id`,
      [JSON.stringify(result), new Date().toISOString(), scan.scanId, owner, new Date().toISOString()])).length === 1;
  }
  async fail(scan: ScanJob, owner: string, code: string, retryable: boolean, backoffMs = 1000 * 2 ** scan.attempts) {
    const state = retryable && scan.attempts < scan.maxAttempts ? "QUEUED" : "DEAD_LETTER";
    return (await this.query(`UPDATE cp_scans SET state = ?, last_error = ?, next_attempt_at = ?, lease_owner = NULL,
      lease_expires_at = NULL, updated_at = ? WHERE scan_id = ? AND state = 'RUNNING' AND lease_owner = ? RETURNING scan_id`,
      [state, JSON.stringify({ code, retryable }), new Date(Date.now() + backoffMs).toISOString(), new Date().toISOString(), scan.scanId, owner])).length === 1;
  }
  async retry(tenantId: string, scanId: string) {
    return (await this.query(`UPDATE cp_scans SET state = 'QUEUED', attempts = 0, stage = 'PENDING', last_error = NULL,
      next_attempt_at = ?, updated_at = ? WHERE tenant_id = ? AND scan_id = ? AND state = 'DEAD_LETTER' RETURNING scan_id`,
      [new Date().toISOString(), new Date().toISOString(), tenantId, scanId])).length === 1;
  }
}
