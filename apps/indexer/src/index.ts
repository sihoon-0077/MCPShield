import { JsonRpcProvider } from "ethers";
import {
  createReleaseRegistry,
  statusFromChain,
} from "../../../packages/contracts-sdk/src/index.js";
import { Repository } from "../../api/src/repository.js";

const rpcUrl = process.env.RPC_URL;
const registryAddress = process.env.REGISTRY_ADDRESS;
const apiUrl = process.env.API_URL ?? "http://127.0.0.1:3001";
if (!rpcUrl || !registryAddress) {
  throw new Error("Set RPC_URL and REGISTRY_ADDRESS");
}

const provider = new JsonRpcProvider(rpcUrl);
const registry = createReleaseRegistry(registryAddress, provider);
const repository = new Repository(process.env.DATABASE_PATH ?? "./mcpshield.db");

registry.on("StatusChanged", async (key, previous, next, event) => {
  const release = await registry.getRelease(key);
  const payload = {
    schemaVersion: "1.0.0",
    releaseId: release.releaseId,
    previousStatus: statusFromChain(previous),
    newStatus: statusFromChain(next),
    txHash: event.log.transactionHash,
    blockNumber: event.log.blockNumber,
  };
  repository.setProjectedStatus(
    release.releaseId,
    payload.newStatus,
    payload.txHash,
    payload.blockNumber,
  );
  console.log(JSON.stringify({ apiUrl, event: payload }));
});

console.log(JSON.stringify({ status: "listening", registryAddress, rpcUrl }));

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, async () => {
    await registry.removeAllListeners();
    repository.close();
    process.exit(0);
  });
}
