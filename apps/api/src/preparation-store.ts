import { randomUUID } from "node:crypto";
import type { ControlStore } from "./control-store.js";
import { hash } from "./control-plane.js";

export interface PreparationJob {
  preparationId: string; tenantId: string; sourceReleaseId: string; policyHash: string; configHash: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "DEAD_LETTER";
  attempts: number; maxAttempts: number; leaseOwner?: string; leaseExpiresAt?: string;
  createdAt: string; updatedAt: string; traceId: string; request: Record<string, any>;
  result?: Record<string, any>; lastError?: { code: string; retryable: boolean };
}
const decode = (row: Record<string, any>): PreparationJob => ({ preparationId: row.preparation_id, tenantId: row.tenant_id,
  sourceReleaseId: row.source_release_id, policyHash: row.policy_hash, configHash: row.config_hash, status: row.state,
  attempts: row.attempts, maxAttempts: row.max_attempts, leaseOwner: row.lease_owner ?? undefined, leaseExpiresAt: row.lease_expires_at ?? undefined,
  createdAt: row.created_at, updatedAt: row.updated_at, traceId: row.trace_id, request: JSON.parse(row.request_json),
  result: row.result_json ? JSON.parse(row.result_json) : undefined, lastError: row.last_error ? JSON.parse(row.last_error) : undefined });
const failure = (message: string, statusCode = 409) => Object.assign(new Error(message), { statusCode });
export async function preparations(store: ControlStore, tenant: string, preparationId?: string) {
  return (await store.query(`SELECT * FROM cp_preparations WHERE tenant_id = ?${preparationId ? " AND preparation_id = ?" : ""} ORDER BY created_at DESC LIMIT 250`,
    [tenant, ...(preparationId ? [preparationId] : [])])).map(decode);
}
export async function enqueuePreparation(store: ControlStore, tenant: string, input: Record<string, any>, key: string, traceId: string) {
  return store.forTenant(tenant, async (tx) => {
    const requestHash = hash({ sourceReleaseId: input.sourceReleaseId, policyHash: input.policyHash, sourceIdentity: input.sourceIdentity });
    const [previous] = await tx.query("SELECT * FROM cp_preparations WHERE tenant_id = ? AND idempotency_key = ?", [tenant, key]);
    if (previous) {
      if (previous.request_hash !== requestHash) throw failure("IDEMPOTENCY_CONFLICT");
      // A retry of the same request never silently replaces its frozen worker configuration.
      return { preparation: decode(previous), deduplicated: true };
    }
    const policy = await tx.get(tenant, "policy", input.policyHash);
    if (!policy || policy.deprecatedAt) throw failure("POLICY_DEPRECATED");
    const usage = await tx.scanUsage(tenant);
    if (usage.today >= policy.document.maxDailyScans || usage.queued >= policy.document.maxQueuedScans) throw failure("SCAN_QUOTA_EXCEEDED", 429);
    const preparationId = randomUUID(), now = new Date().toISOString();
    await tx.query(`INSERT INTO cp_preparations(preparation_id,tenant_id,source_release_id,policy_hash,idempotency_key,request_hash,request_json,
      config_hash,state,next_attempt_at,trace_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'QUEUED',?,?,?,?)`,
      [preparationId, tenant, input.sourceReleaseId, input.policyHash, key, requestHash, JSON.stringify(input), hash(input.trustedConfig), now, traceId, now, now]);
    await tx.event(tenant, input.sourceReleaseId, "preparation.queued", { preparationId }, traceId);
    return { preparation: (await preparations(tx, tenant, preparationId))[0], deduplicated: false };
  });
}
export async function claimPreparation(store: ControlStore, owner: string, leaseMs = 20 * 60 * 1000) {
  // ponytail: tiny global claim transaction; parallel execution remains outside it. Partition only if claim contention is measured.
  return store.forTenant("__preparation_claim", async (tx) => {
    const now = new Date().toISOString();
    const lost = await tx.query(`UPDATE cp_preparations SET state='DEAD_LETTER',last_error=?,lease_owner=NULL,lease_expires_at=NULL,updated_at=?
      WHERE state='RUNNING' AND lease_expires_at<=? AND attempts>=max_attempts RETURNING *`,
      [JSON.stringify({ code: "WORKER_LOST", retryable: true }), now, now]);
    for (const row of lost) await tx.event(row.tenant_id, row.source_release_id, "preparation.failed", { preparationId: row.preparation_id, code: "WORKER_LOST" }, row.trace_id);
    const [row] = await tx.query(`UPDATE cp_preparations SET state='RUNNING',attempts=attempts+1,lease_owner=?,lease_expires_at=?,updated_at=? WHERE preparation_id=(
      SELECT preparation_id FROM cp_preparations WHERE attempts<max_attempts AND ((state='QUEUED' AND next_attempt_at<=?) OR (state='RUNNING' AND lease_expires_at<=?))
      ORDER BY created_at,preparation_id LIMIT 1${store.driver === "POSTGRESQL" ? " FOR UPDATE SKIP LOCKED" : ""}) RETURNING *`,
      [owner, new Date(Date.now() + leaseMs).toISOString(), now, now, now]);
    if (!row) return undefined;
    await tx.event(row.tenant_id, row.source_release_id, "preparation.started", { preparationId: row.preparation_id, attempts: row.attempts }, row.trace_id);
    return decode(row);
  });
}
export async function failPreparation(store: ControlStore, job: PreparationJob, owner: string, code: string, retryable: boolean, backoffMs = 1000 * 2 ** job.attempts) {
  return store.forTenant(job.tenantId, async (tx) => {
    const [row] = await tx.query(`UPDATE cp_preparations SET state=?,last_error=?,next_attempt_at=?,lease_owner=NULL,lease_expires_at=NULL,updated_at=?
      WHERE tenant_id=? AND preparation_id=? AND state='RUNNING' AND lease_owner=? AND lease_expires_at>? RETURNING preparation_id`,
      [retryable && job.attempts < job.maxAttempts ? "QUEUED" : "DEAD_LETTER", JSON.stringify({ code, retryable }), new Date(Date.now() + backoffMs).toISOString(),
        new Date().toISOString(), job.tenantId, job.preparationId, owner, new Date().toISOString()]);
    if (row) await tx.event(job.tenantId, job.sourceReleaseId, "preparation.failed", { preparationId: job.preparationId, code, retryable }, job.traceId);
    return Boolean(row);
  });
}
export async function retryPreparation(store: ControlStore, tenant: string, preparationId: string, trustedConfig: Record<string, any>) {
  return store.forTenant(tenant, async (tx) => {
    const [job] = await preparations(tx, tenant, preparationId);
    if (!job) throw failure("PREPARATION_NOT_FOUND", 404);
    if (job.status !== "DEAD_LETTER" || !job.lastError?.retryable) throw failure("PREPARATION_NOT_RETRYABLE");
    if (job.configHash !== hash(trustedConfig)) throw failure("PREPARATION_CONFIG_CHANGED");
    const policy = await tx.get(tenant, "policy", job.policyHash);
    if (!policy || policy.deprecatedAt) throw failure("POLICY_DEPRECATED");
    const usage = await tx.scanUsage(tenant);
    if (usage.queued >= policy.document.maxQueuedScans) throw failure("SCAN_QUOTA_EXCEEDED", 429);
    await tx.query(`UPDATE cp_preparations SET state='QUEUED',attempts=0,last_error=NULL,next_attempt_at=?,updated_at=? WHERE tenant_id=? AND preparation_id=? AND state='DEAD_LETTER'`,
      [new Date().toISOString(), new Date().toISOString(), tenant, preparationId]);
    await tx.event(tenant, job.sourceReleaseId, "preparation.retried", { preparationId }, job.traceId);
    return (await preparations(tx, tenant, preparationId))[0];
  });
}
export function publicPreparation({ tenantId: _tenant, request: _request, leaseOwner: _owner, leaseExpiresAt: _lease, configHash: _config, result, ...job }: PreparationJob) {
  if (!result) return job;
  const { evidenceKey: _key, ...safeResult } = result; return { ...job, result: safeResult };
}
