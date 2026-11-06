import type { ControlOptions } from "./control-plane.js";
import type { ControlStore } from "./control-store.js";
import { HEARTBEAT_KIND, scannerHealth } from "./worker-health.js";

export type HealthComponent = { status: "UP" | "DOWN" | "UNKNOWN" | "NOT_CONFIGURED" | "LIMITED"; code: string; checkedAt: string | null };
const component = (status: HealthComponent["status"], code: string, checkedAt: string | null = null): HealthComponent => ({ status, code, checkedAt });
const timedOut = Symbol("HEALTH_PROBE_TIMEOUT");
const chainDownCodes = new Set(["CHAIN_ID_MISMATCH", "CHAIN_HEAD_INVALID", "CHAIN_HEAD_STALE", "CHAIN_REGISTRY_UNAVAILABLE", "CHAIN_TRANSPORT_UNAVAILABLE", "CHAIN_TRUST_REJECTED", "CHAIN_READER_CLOSED"]);

// Cache is only an availability display, never an admission decision. A timed-out
// raw operation keeps its slot until settled, so repeated requests cannot pile up work.
function cachedProbe<T>(work: () => Promise<T>, failed: (timeout: boolean) => T) {
  let current: { promise: Promise<T>; pending: boolean; completedAt?: number } | undefined;
  return () => {
    if (current && (current.pending || current.completedAt === undefined || Date.now() - current.completedAt < 2000)) return current.promise;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const entry = { pending: true } as NonNullable<typeof current>;
    const raw = Promise.resolve().then(work);
    void raw.finally(() => { entry.pending = false; }).catch(() => {});
    entry.promise = Promise.race([raw, new Promise<never>((_, reject) => { timer = setTimeout(() => reject(timedOut), 2000); })])
      .catch(error => failed(error === timedOut)).finally(() => { clearTimeout(timer); entry.completedAt = Date.now(); });
    current = entry; return entry.promise;
  };
}

export function createControlHealth(store: ControlStore, options: ControlOptions) {
  const chain = cachedProbe(async () => {
    if (!options.chainDecision) return component(options.v2Relayer ? "UNKNOWN" : "NOT_CONFIGURED", options.v2Relayer ? "CHAIN_PROBE_NOT_AVAILABLE" : "CHAIN_NOT_CONFIGURED");
    if (typeof options.chainDecision.health !== "function") return component("UNKNOWN", "CHAIN_PROBE_NOT_AVAILABLE");
    const result = await options.chainDecision.health(), checkedAt = new Date().toISOString();
    if (result?.status === "UP" && result.code === "CHAIN_READY") return component("UP", result.code, checkedAt);
    if (result?.status === "DOWN" && chainDownCodes.has(result.code)) return component("DOWN", result.code, checkedAt);
    return component("UNKNOWN", "CHAIN_PROBE_INVALID");
  }, timeout => component("DOWN", timeout ? "CHAIN_PROBE_TIMEOUT" : "CHAIN_PROBE_FAILED", new Date().toISOString()));
  const tenants = new Map([...new Set(options.credentials.map(value => value.tenantId))].map(tenantId => [tenantId, cachedProbe<{ database: HealthComponent; rows?: Record<string, any>[] }>(async () => {
    // One real, tenant-scoped DB read also obtains a bounded heartbeat inventory.
    const rows = await store.query("SELECT document,created_at FROM cp_records WHERE tenant_id=? AND kind=? ORDER BY created_at DESC,id LIMIT 65", [tenantId, HEARTBEAT_KIND], 100);
    return { database: component("UP", "DATABASE_READY", new Date().toISOString()), rows };
  }, timeout => ({ database: component("DOWN", timeout ? "DATABASE_TIMEOUT" : "DATABASE_UNAVAILABLE", new Date().toISOString()), rows: undefined }))]));
  return async (tenantId: string) => {
    const read = tenants.get(tenantId); if (!read) throw Error("UNAUTHORIZED");
    const [storage, chainStatus] = await Promise.all([read(), chain()]);
    const checkedAt = new Date().toISOString(), components = { api: component("UP", "API_READY", checkedAt), database: storage.database, chain: chainStatus,
      scanner: storage.rows ? scannerHealth(storage.rows) : component("UNKNOWN", "SCANNER_DATABASE_UNAVAILABLE") };
    return { schemaVersion: "mcpshield.health.v1", status: Object.values(components).every(value => value.status === "UP") ? "READY" : "DEGRADED", checkedAt, components };
  };
}
