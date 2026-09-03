import { JsonRpcProvider } from "ethers";
import { writeFile } from "node:fs/promises";
import { createReleaseRegistry } from "../../../packages/contracts-sdk/src/index.js";
import { Repository } from "../../api/src/repository.js";
import { ChainIndexer } from "./indexer.js";

const rpcUrl = process.env.RPC_URL;
const registryAddress = process.env.REGISTRY_ADDRESS;
if (!rpcUrl || !registryAddress) throw new Error("Set RPC_URL and REGISTRY_ADDRESS");
const deploymentBlock = Number(process.env.DEPLOYMENT_BLOCK);
if (!Number.isSafeInteger(deploymentBlock) || deploymentBlock < 0) {
  throw new Error("DEPLOYMENT_BLOCK must be a non-negative integer");
}
const provider = new JsonRpcProvider(rpcUrl);
const repository = new Repository(process.env.DATABASE_PATH ?? "./mcpshield.db");
const indexer = new ChainIndexer(provider, createReleaseRegistry(registryAddress, provider),
  repository, registryAddress, deploymentBlock, Number(process.env.CONFIRMATION_DEPTH || 3),
  Number(process.env.REORG_REWIND_BLOCKS || 20));
let stopped = false;
for (const signal of ["SIGINT", "SIGTERM"] as const) process.on(signal, () => { stopped = true; });
while (!stopped) {
  await indexer.syncOnce();
  if (process.env.INDEXER_HEALTH_PATH) {
    await writeFile(process.env.INDEXER_HEALTH_PATH, new Date().toISOString(), "utf8");
  }
  await new Promise((resolve) => setTimeout(resolve, Number(process.env.POLL_INTERVAL_MS || 3000)));
}
repository.close();
