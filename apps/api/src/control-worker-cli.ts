import { setTimeout } from "node:timers/promises";
import { ControlStore } from "./control-store.js";
import { runControlWorkerOnce } from "./control-worker.js";
import { controlConfig } from "./control-config.js";

const options = controlConfig();
if (!options) throw new Error("CONTROL_PLANE_ENABLED=true is required");
const store = await ControlStore.open(options.databaseUrl);
let stopped = false;
for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => { stopped = true; });
try {
  while (!stopped) {
    const worked = await runControlWorkerOnce(store, options);
    if (process.argv.includes("--once")) break;
    if (!worked) await setTimeout(1000);
  }
} finally { await store.close(); }
