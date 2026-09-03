import { readFile } from "node:fs/promises";
import path from "node:path";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const file = process.env.MCPSHIELD_REPLAY_FILE ?? path.resolve(process.cwd(), "../../scripts/demo/replay.json");
    const replay = JSON.parse(await readFile(/* turbopackIgnore: true */ file, "utf8"));
    return Response.json({ ...replay.snapshot, source: "REPLAY" });
  } catch (error) {
    return Response.json({ error: "Replay unavailable", detail: error instanceof Error ? error.message : "unknown error" }, { status: 503 });
  }
}
