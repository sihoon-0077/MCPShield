import { DatabaseSync } from "node:sqlite";
import { readFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import type { Pool } from "pg";

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
  private constructor() {}
  static async open(location = ":memory:") {
    const store = new ControlStore();
    if (/^postgres(?:ql)?:\/\//.test(location)) {
      const { Pool } = await import("pg");
      store.pool = new Pool({ connectionString: location, max: 10, connectionTimeoutMillis: 5000, statement_timeout: 10000 });
    } else {
      if (location !== ":memory:") mkdirSync(dirname(resolve(location)), { recursive: true });
      store.sqlite = new DatabaseSync(location);
      store.sqlite.exec("PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL;");
    }
    const sql = readFileSync(fileURLToPath(new URL("../../../database/migrations/002_control_plane.sql", import.meta.url)), "utf8");
    if (store.sqlite) store.sqlite.exec(sql); else await store.pool!.query(sql);
    const audit = readFileSync(fileURLToPath(new URL(`../../../database/migrations/003_scan_audit.${store.pool ? "pg" : "sqlite"}.sql`, import.meta.url)), "utf8");
    if (store.sqlite) store.sqlite.exec(audit); else await store.pool!.query(audit);
    const chain = readFileSync(fileURLToPath(new URL("../../../database/migrations/004_chain_outbox.sql", import.meta.url)), "utf8");
    if (store.sqlite) store.sqlite.exec(chain); else await store.pool!.query(chain);
    return store;
  }
  get driver() { return this.pool ? "POSTGRESQL" : "SQLITE"; }
  async close() { if (this.pool) await this.pool.end(); else this.sqlite?.close(); }
  async query(sql: string, values: Array<string | number | null> = []): Promise<Record<string, any>[]> {
    if (this.pool) { let index = 0; return (await this.pool.query(sql.replace(/\?/g, () => `$${++index}`), values)).rows; }
    return this.sqlite!.prepare(sql).all(...values) as Record<string, any>[];
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
  async idempotentScan(tenantId: string, key: string, requestHash: string) {
    const [row] = await this.query("SELECT * FROM cp_scans WHERE tenant_id = ? AND idempotency_key = ?", [tenantId, key]);
    if (row && row.request_hash !== requestHash) throw Object.assign(new Error("IDEMPOTENCY_CONFLICT"), { statusCode: 409 });
    return row ? job(row) : undefined;
  }
  async scanUsage(tenantId: string) {
    const counts: Record<string, number> = { QUEUED: 0, RUNNING: 0, COMPLETED: 0, DEAD_LETTER: 0 };
    for (const row of await this.query("SELECT state, COUNT(*) AS count FROM cp_scans WHERE tenant_id = ? GROUP BY state", [tenantId])) counts[row.state] = Number(row.count);
    const [daily] = await this.query("SELECT COUNT(*) AS count FROM cp_scans WHERE tenant_id = ? AND created_at >= ?", [tenantId, new Date().toISOString().slice(0, 10)]);
    return { counts, today: Number(daily.count), queued: counts.QUEUED + counts.RUNNING };
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
