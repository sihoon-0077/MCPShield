import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const stateDir = join(here, ".state");
await rm(stateDir, { recursive: true, force: true });
await mkdir(stateDir, { recursive: true });
await writeFile(join(stateDir, "session.json"), JSON.stringify({ status: "RESET", resetAt: new Date().toISOString() }, null, 2));
console.log("MCPShield demo reset complete (mode: REPLAY)");
