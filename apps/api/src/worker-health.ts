import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promisify } from "node:util";
import type { ControlOptions } from "./control-plane.js";
import type { ControlStore } from "./control-store.js";
import type { HealthComponent } from "./control-health.js";

export const HEARTBEAT_KIND = "scannerHeartbeat", HEARTBEAT_TTL_MS = 20_000;
const run = promisify(execFile), schemaVersion = "mcpshield.scanner-heartbeat.v1";
type Probe = { status: "UP" | "DOWN"; code: "DOCKER_AVAILABLE" | "DOCKER_UNAVAILABLE" | "DOCKER_TIMEOUT" };
const isoTime = (value: unknown) => typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;

export async function probeScannerDocker(): Promise<Probe> {
  try {
    const { stdout } = await run("docker", ["info", "--format", "{{json .OSType}}"], { timeout: 1500, killSignal: "SIGKILL", maxBuffer: 1024, windowsHide: true });
    return JSON.parse(stdout) === "linux" ? { status: "UP", code: "DOCKER_AVAILABLE" } : { status: "DOWN", code: "DOCKER_UNAVAILABLE" };
  } catch (error: any) { return { status: "DOWN", code: error?.signal === "SIGKILL" ? "DOCKER_TIMEOUT" : "DOCKER_UNAVAILABLE" }; }
}

// Only the trusted worker calls this writer. Public API credentials cannot write cp_records.
// The probe override is an explicit in-process test seam, never an environment/API option.
export function startScannerHeartbeat(store: ControlStore, options: ControlOptions, mode: "ALL" | "SCAN" | "CHAIN_ONLY",
  probe: () => Promise<Probe> = probeScannerDocker) {
  const tenants = [...new Set(options.credentials.filter(value => ["admin", "operator"].includes(value.role) && /^[a-zA-Z0-9_-]{1,64}$/.test(value.tenantId)).map(value => value.tenantId))];
  const id = randomUUID(), sandbox = options.scannerOptions?.sandbox === "docker" ? "DOCKER" : "STATIC_ONLY";
  let stopped = mode === "CHAIN_ONLY" || !tenants.length, timer: ReturnType<typeof setTimeout> | undefined, active: Promise<void> | undefined;
  const write = async (state: "RUNNING" | "STOPPED", observation: { status: string; code: string; checkedAt: string }) => {
    const updatedAt = new Date().toISOString();
    const document = JSON.stringify({ schemaVersion, mode, state, sandbox, probe: observation, updatedAt });
    for (const tenant of tenants) {
      if (state === "RUNNING" && stopped) return;
      await store.query(`INSERT INTO cp_records(tenant_id,kind,id,document,created_at) VALUES(?,?,?,?,?)
        ON CONFLICT(tenant_id,kind,id) DO UPDATE SET document=excluded.document,created_at=excluded.created_at`, [tenant, HEARTBEAT_KIND, id, document, updatedAt]);
      // Ephemeral liveness observations, not audit/evidence: retain two minutes for diagnosis.
      await store.query("DELETE FROM cp_records WHERE tenant_id=? AND kind=? AND created_at<? AND id<>?", [tenant, HEARTBEAT_KIND, new Date(Date.now() - 120_000).toISOString(), id]);
    }
  };
  const pulse = (): Promise<void> => {
    if (stopped) return Promise.resolve();
    if (active) return active;
    active = (async () => {
      let result: { status: string; code: string } = { status: "LIMITED", code: "STATIC_ONLY" };
      if (sandbox === "DOCKER") {
        let deadline: ReturnType<typeof setTimeout> | undefined;
        // The native probe also kills its subprocess; this outer fence bounds trusted injected probes.
        try { result = await Promise.race([probe(), new Promise<Probe>(resolve => { deadline = setTimeout(() => resolve({ status: "DOWN", code: "DOCKER_TIMEOUT" }), 2000); })]); }
        catch { result = { status: "DOWN", code: "DOCKER_UNAVAILABLE" }; }
        finally { clearTimeout(deadline); }
        if (!(result.status === "UP" && result.code === "DOCKER_AVAILABLE") && !(result.status === "DOWN" && ["DOCKER_UNAVAILABLE", "DOCKER_TIMEOUT"].includes(result.code))) result = { status: "DOWN", code: "DOCKER_UNAVAILABLE" };
      }
      await write("RUNNING", { ...result, checkedAt: new Date().toISOString() });
    })().finally(() => { active = undefined; });
    return active;
  };
  const tick = () => { void pulse().catch(() => console.error('{"event":"scanner.heartbeat.failed","code":"HEARTBEAT_STORAGE_UNAVAILABLE"}')).finally(() => {
    if (!stopped) { timer = setTimeout(tick, 5000); timer.unref(); }
  }); };
  if (!stopped) tick();
  return { pulse, async stop() {
    if (stopped) return;
    stopped = true; clearTimeout(timer);
    // No write races with STOPPED. Native SQL has bounded pool/statement timeouts;
    // if shutdown cannot finish its last write, the existing observation expires by TTL.
    let deadline: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([(async () => {
        await active?.catch(() => {});
        await write("STOPPED", { status: "DOWN", code: "WORKER_STOPPED", checkedAt: new Date().toISOString() });
      })(), new Promise<never>((_, reject) => { deadline = setTimeout(() => reject(Error("HEARTBEAT_STOP_TIMEOUT")), 2000); })]);
    } catch { console.error('{"event":"scanner.heartbeat.stopped","code":"HEARTBEAT_STORAGE_UNAVAILABLE"}'); }
    finally { clearTimeout(deadline); }
  } };
}

export function scannerHealth(rows: Record<string, any>[], now = Date.now()): HealthComponent {
  const component = (status: HealthComponent["status"], code: string, checkedAt: string | null = null) => ({ status, code, checkedAt });
  if (!rows.length) return component("UNKNOWN", "SCANNER_HEARTBEAT_MISSING");
  const observations = rows.slice(0, 64).map(row => {
    let value: any;
    try { value = JSON.parse(row.document); } catch { return component("UNKNOWN", "SCANNER_HEARTBEAT_INVALID"); }
    if (!value || Object.keys(value).sort().join() !== "mode,probe,sandbox,schemaVersion,state,updatedAt" || value.schemaVersion !== schemaVersion
      || !["ALL", "SCAN"].includes(value.mode) || !["RUNNING", "STOPPED"].includes(value.state) || !["DOCKER", "STATIC_ONLY"].includes(value.sandbox)
      || !value.probe || Object.keys(value.probe).sort().join() !== "checkedAt,code,status" || !isoTime(value.updatedAt) || !isoTime(value.probe.checkedAt)
      || row.created_at !== value.updatedAt) return component("UNKNOWN", "SCANNER_HEARTBEAT_INVALID");
    if (Date.parse(value.updatedAt) > now || Date.parse(value.probe.checkedAt) > now || Date.parse(value.probe.checkedAt) > Date.parse(value.updatedAt)) return component("UNKNOWN", "SCANNER_CLOCK_INVALID");
    if (now - Date.parse(value.updatedAt) > HEARTBEAT_TTL_MS || now - Date.parse(value.probe.checkedAt) > HEARTBEAT_TTL_MS) return component("DOWN", "SCANNER_HEARTBEAT_STALE", value.probe.checkedAt);
    if (value.state === "STOPPED" && value.probe.status === "DOWN" && value.probe.code === "WORKER_STOPPED") return component("DOWN", "SCANNER_STOPPED", value.probe.checkedAt);
    if (value.state === "RUNNING") {
      if (value.sandbox === "STATIC_ONLY" && value.probe.status === "LIMITED" && value.probe.code === "STATIC_ONLY") return component("LIMITED", "SCANNER_STATIC_ONLY", value.probe.checkedAt);
      if (value.sandbox === "DOCKER") {
        if (value.probe.status === "UP" && value.probe.code === "DOCKER_AVAILABLE") return component("UP", "SCANNER_DOCKER_READY", value.probe.checkedAt);
        if (value.probe.status === "DOWN" && ["DOCKER_UNAVAILABLE", "DOCKER_TIMEOUT"].includes(value.probe.code)) return component("DOWN", `SCANNER_${value.probe.code}`, value.probe.checkedAt);
      }
    }
    return component("UNKNOWN", "SCANNER_HEARTBEAT_INVALID");
  });
  return observations.find(value => value.status === "UP") ?? observations.find(value => value.status === "LIMITED")
    ?? (rows.length > 64 ? component("UNKNOWN", "SCANNER_INVENTORY_TRUNCATED") : observations.find(value => value.status === "UNKNOWN") ?? observations[0]);
}
