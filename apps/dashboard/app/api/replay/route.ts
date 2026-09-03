import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Snapshot } from "../../../lib/types";

export const dynamic = "force-dynamic";

function isSnapshot(value: unknown): value is Snapshot {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<Snapshot>;
  return candidate.schemaVersion === "1.0.0" &&
    typeof candidate.generatedAt === "string" && !Number.isNaN(Date.parse(candidate.generatedAt)) &&
    Array.isArray(candidate.releases) && Array.isArray(candidate.pipeline) &&
    Array.isArray(candidate.sandboxEvents) && Array.isArray(candidate.validators) &&
    Array.isArray(candidate.admissions);
}

export async function GET() {
  try {
    const file = process.env.MCPSHIELD_REPLAY_FILE ?? path.resolve(process.cwd(), "../../scripts/demo/replay.json");
    const replay = JSON.parse(await readFile(/* turbopackIgnore: true */ file, "utf8"));
    if (!isSnapshot(replay.snapshot)) throw new Error("Replay snapshot does not match schema v1");
    return Response.json({ ...replay.snapshot, source: "REPLAY", ledgerMode: "OFFLINE" }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    return Response.json({ error: "Replay unavailable", detail: error instanceof Error ? error.message : "unknown error" }, { status: 503 });
  }
}
