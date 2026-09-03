import { Interface, JsonRpcProvider, type Log } from "ethers";
import {
  createReleaseRegistry,
  releaseRegistryAbi,
  statusFromChain,
} from "../../../packages/contracts-sdk/src/index.js";
import { Repository } from "../../api/src/repository.js";

const rpcUrl = process.env.RPC_URL;
const registryAddress = process.env.REGISTRY_ADDRESS;
if (!rpcUrl || !registryAddress) throw new Error("Set RPC_URL and REGISTRY_ADDRESS");
const deploymentBlock = Number(process.env.DEPLOYMENT_BLOCK);
if (!Number.isSafeInteger(deploymentBlock) || deploymentBlock < 0) {
  throw new Error("DEPLOYMENT_BLOCK must be a non-negative integer");
}

const provider = new JsonRpcProvider(rpcUrl);
const registry = createReleaseRegistry(registryAddress, provider);
const abi = new Interface(releaseRegistryAbi);
const repository = new Repository(process.env.DATABASE_PATH ?? "./mcpshield.db");
const checkpointName = `release-registry:${registryAddress.toLowerCase()}`;
let stopped = false;

async function releaseForKey(key: string) {
  const item = await registry.getRelease(key);
  return {
    releaseId: item.releaseId as string,
    artifactDigest: `sha256:${String(item.artifactDigest).slice(2).toLowerCase()}`,
    toolSurfaceHash: String(item.toolSurfaceHash).toLowerCase(),
    status: statusFromChain(item.status),
  };
}

async function processLog(log: Log) {
  const parsed = abi.parseLog(log);
  if (!parsed) return;
  let release;
  if (parsed.name === "ReleaseRegistered") {
    release = {
      releaseId: parsed.args.releaseId as string,
      artifactDigest: `sha256:${String(parsed.args.artifactDigest).slice(2).toLowerCase()}`,
      toolSurfaceHash: String(parsed.args.toolSurfaceHash).toLowerCase(),
      status: "UNVERIFIED" as const,
    };
    repository.upsertIndexedRelease({
      releaseId: release.releaseId,
      artifactDigest: release.artifactDigest,
      toolSurfaceHash: release.toolSurfaceHash,
    });
  } else {
    release = await releaseForKey(parsed.args.releaseKey as string);
  }
  if (parsed.name === "StatusChanged") {
    repository.setProjectedStatus(release.releaseId, statusFromChain(parsed.args.newStatus));
  }
  repository.recordIndexedEvent({
    releaseId: release.releaseId,
    eventName: parsed.name,
    status: parsed.name === "StatusChanged" ? statusFromChain(parsed.args.newStatus) : release.status,
    txHash: log.transactionHash,
    blockNumber: log.blockNumber,
    logIndex: log.index,
    payload: { indexed: true },
  });
}

async function sync() {
  const latest = await provider.getBlockNumber();
  let from = (repository.getCheckpoint(checkpointName) ?? deploymentBlock - 1) + 1;
  while (from <= latest) {
    const to = Math.min(from + 999, latest);
    const logs = await provider.getLogs({ address: registryAddress, fromBlock: from, toBlock: to });
    for (const log of logs) await processLog(log);
    repository.setCheckpoint(checkpointName, to);
    from = to + 1;
  }
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    stopped = true;
  });
}

console.log(JSON.stringify({ status: "backfilling", registryAddress, deploymentBlock }));
while (!stopped) {
  await sync();
  await new Promise((resolve) => setTimeout(resolve, Number(process.env.POLL_INTERVAL_MS ?? 3000)));
}
repository.close();
