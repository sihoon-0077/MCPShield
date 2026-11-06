// Runs the capstone v2.1 consortium scene (ADR-004/006) on a local EVM and writes a provenance-bound
// JSON result. Local measurement only: not Base Sepolia, not a Docker scan. Refuses to publish a run
// whose scene invariants fail, and never overwrites an existing result.
import { parseArgs } from "node:util";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { withSourceProvenance } from "./evaluate-admission.js";

const { values } = parseArgs({ options: { samples: { type: "string", default: "50" }, "poll-ms": { type: "string", default: "50" },
  out: { type: "string" }, "allow-dirty": { type: "boolean", default: false } } });
const samples = Number(values.samples), pollIntervalMs = Number(values["poll-ms"]);
if (!Number.isSafeInteger(samples) || samples < 1 || samples > 1000) throw Error("--samples must be 1..1000");
if (!Number.isSafeInteger(pollIntervalMs) || pollIntervalMs < 10 || pollIntervalMs > 1000) throw Error("--poll-ms must be 10..1000");

// Ambient Gateway/telemetry settings must not change what the in-process library rows measure.
for (const key of Object.keys(process.env)) if (/^(MCPSHIELD_|OTEL_)/.test(key)) delete process.env[key];
process.env.MCPSHIELD_TELEMETRY_ENABLED = "false";

const result = await withSourceProvenance(async () => {
  // Snapshot before importing the code that will actually be measured.
  const scene = await import("../../tests/integration/consortium-scene.js");
  const report = await scene.runConsortiumScene({ latencySamples: samples, pollIntervalMs, log: (line: string) => process.stderr.write(`${line}\n`) });
  scene.assertConsortiumReport(report, samples);
  return report;
});
if (result.worktreeDirty && !values["allow-dirty"]) throw Error("NOT_PUBLISHABLE: worktree is dirty; commit first or pass --allow-dirty (recorded in the result)");
const measuredAt = new Date().toISOString();
const dirty = result.worktreeDirty ? `-dirty-${result.provenance.start.sourceHash.slice(0, 8)}` : "";
const out = values.out ?? join("benchmarks", "results", `consortium-scene-${result.sourceCommit.slice(0, 7)}${dirty}-${measuredAt.replace(/[:.]/g, "-")}.json`);
await mkdir(dirname(out), { recursive: true });
await writeFile(out, `${JSON.stringify({ ...result, measuredAt, samples, pollIntervalMs, allowDirty: values["allow-dirty"] }, null, 2)}\n`, { flag: "wx" });
const scenes = result.scenes, latency = result.measurements.toolCallLatencyMs;
process.stdout.write(`${JSON.stringify({ out,
  approved: [scenes.approved.inspect.gatewayA.decision, scenes.approved.inspect.gatewayB.decision],
  operatorOutage: { gatewayA: scenes.operatorOutage.toolCallDuringOutage.gatewayA.gatewayBlocked, gatewayB: scenes.operatorOutage.toolCallDuringOutage.gatewayB.ok },
  revoked: [scenes.revoked.gatewayA.releaseStatus, scenes.revoked.gatewayB.releaseStatus, scenes.revoked.gatewayA.refusedBeforeSpawn, scenes.revoked.gatewayB.refusedBeforeSpawn],
  operatorCompromised: { gatewayAFirstSight: scenes.operatorCompromised.gatewayAFirstSight.decision, gatewayAWithJournal: scenes.operatorCompromised.gatewayAWithJournal.gatewayErrorClass,
    gatewayB: scenes.operatorCompromised.gatewayB.releaseStatus },
  quarantinePropagationMs: result.measurements.quarantinePropagationMs,
  toolCallMs: { direct: latency.direct, gatewayA: latency.gatewayA, gatewayB: latency.gatewayB } }, null, 2)}\n`);
