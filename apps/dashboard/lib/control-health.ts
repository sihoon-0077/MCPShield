export const healthComponents = ["api", "database", "chain", "scanner"] as const;
export type HealthComponent = { status: "UP" | "DOWN" | "UNKNOWN" | "NOT_CONFIGURED" | "LIMITED"; code: string; checkedAt: string | null };
export type ControlHealth = { schemaVersion: "mcpshield.health.v1"; status: "READY" | "DEGRADED"; checkedAt: string; components: Record<typeof healthComponents[number], HealthComponent> };
const record = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const keys = (value: Record<string, unknown>, expected: readonly string[]) => Object.keys(value).sort().join() === [...expected].sort().join();
const iso = (value: unknown): value is string => typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;

// A 503 is a report only when the entire versioned contract and HTTP status agree.
export function parseControlHealth(value: unknown, httpStatus: number): ControlHealth {
  if (!record(value) || !keys(value, ["schemaVersion", "status", "checkedAt", "components"]) || value.schemaVersion !== "mcpshield.health.v1"
    || typeof value.status !== "string" || !["READY", "DEGRADED"].includes(value.status) || !iso(value.checkedAt) || !record(value.components) || !keys(value.components, healthComponents)) throw new Error("INVALID_CONTROL_HEALTH");
  for (const name of healthComponents) {
    const item = value.components[name];
    if (!record(item) || !keys(item, ["status", "code", "checkedAt"]) || typeof item.status !== "string" || !["UP", "DOWN", "UNKNOWN", "NOT_CONFIGURED", "LIMITED"].includes(item.status)
      || typeof item.code !== "string" || !/^[A-Z][A-Z0-9_]{0,79}$/.test(item.code) || !(item.checkedAt === null || iso(item.checkedAt))
      || item.status === "UP" && item.checkedAt === null || typeof item.checkedAt === "string" && Date.parse(item.checkedAt) > Date.parse(value.checkedAt)) throw new Error("INVALID_CONTROL_HEALTH");
  }
  const ready = healthComponents.every(name => (value.components as Record<string, HealthComponent>)[name].status === "UP");
  if (value.status !== (ready ? "READY" : "DEGRADED") || httpStatus !== (ready ? 200 : 503)) throw new Error("INVALID_CONTROL_HEALTH");
  return value as ControlHealth;
}
