import { setTimeout } from "node:timers/promises";
import { ControlStore } from "./control-store.js";
import { runControlWorkerOnce } from "./control-worker.js";
import { controlConfig } from "./control-config.js";
import { runChainActionOnce, reconcileV2Actions } from "./chain-outbox.js";
import { indexV2 } from "../../indexer/src/v2-indexer.js";

const options = controlConfig();
if (!options) throw new Error("CONTROL_PLANE_ENABLED=true is required");
const store = await ControlStore.open(options.databaseUrl);
let stopped = false;
for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => { stopped = true; });
try {
  while (!stopped) {
    const worked = !process.argv.includes("--chain-only") && await runControlWorkerOnce(store, options);
    const chainWorked = options.v2Relayer && !process.argv.includes("--scan-only") ? await runChainActionOnce(store, options.v2Relayer) : false;
    if (options.v2Relayer && !process.argv.includes("--scan-only")) {
      try {
        await reconcileV2Actions(store, options.v2Relayer);
        await indexV2(store, options.v2Relayer, { deploymentBlock: Number(process.env.CONTROL_V2_DEPLOYMENT_BLOCK ?? 0), confirmations: Number(process.env.CONTROL_V2_CONFIRMATIONS ?? 2) });
      } catch { console.error(JSON.stringify({ event: "chain.synchronization.failed", code: "RPC_UNAVAILABLE" })); }
    }
    if (process.argv.includes("--once")) break;
    if (!worked) await setTimeout(1000);
  }
} finally { await store.close(); options.v2Relayer?.close(); if (options.chainDecision && "close" in options.chainDecision) (options.chainDecision as any).close(); }
