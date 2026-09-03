import assert from "node:assert/strict";
import { test } from "node:test";
import { Interface, type Log } from "ethers";
import { ChainIndexer } from "../../apps/indexer/src/indexer.js";
import { Repository } from "../../apps/api/src/repository.js";
import { releaseRegistryAbi, releaseKey } from "../../packages/contracts-sdk/src/index.js";

const address = "0x0000000000000000000000000000000000000042";
const validator = "0x0000000000000000000000000000000000000001";
const digestBytes = `0x${"a".repeat(64)}`;
const digest = `sha256:${"a".repeat(64)}`;
const toolHash = `0x${"b".repeat(64)}`;
const evidenceHash = `0x${"c".repeat(64)}`;
const releaseId = "mail-mcp@1.0.1";
const key = releaseKey(releaseId);
const abi = new Interface(releaseRegistryAbi);
function makeLog(event: string, args: unknown[], blockNumber: number, marker: string): Log {
  const encoded = abi.encodeEventLog(abi.getEvent(event)!, args);
  return { address, topics: encoded.topics, data: encoded.data, blockNumber,
    transactionHash: `0x${marker.repeat(64)}`, index: 0, transactionIndex: 0,
    blockHash: `0x${String(blockNumber).padStart(64, "0")}`, removed: false } as unknown as Log;
}

test("indexer deduplicates, recovers votes and rewinds orphaned projections", async () => {
  const repository = new Repository(":memory:");
  try {
    let block4Hash = `0x${"4".repeat(64)}`;
    let includeStatus = true;
    const logs = [makeLog("ReleaseRegistered", [key, releaseId, digestBytes, toolHash], 1, "1"),
      makeLog("VoteSubmitted", [key, validator, 1, evidenceHash, 0], 2, "2"),
      makeLog("StatusChanged", [key, 0, 2], 3, "3")];
    const provider = { async getNetwork() { return { chainId: 31337n }; },
      async getBlockNumber() { return 5; },
      async getBlock(blockNumber: number) { return { hash: blockNumber === 4 ? block4Hash : `0x${String(blockNumber).padStart(64, "0")}` }; },
      async getLogs(filter: { fromBlock: number; toBlock: number }) { return logs.filter((item) => item.blockNumber >= filter.fromBlock && item.blockNumber <= filter.toBlock && (includeStatus || item.blockNumber !== 3)); } };
    const registry = { async getRelease() { return { releaseId, artifactDigest: digestBytes, toolSurfaceHash: toolHash, status: 2n }; }, async nonces() { return 1n; } };
    const indexer = new ChainIndexer(provider, registry, repository, address, 1, 1, 2);
    await indexer.syncOnce();
    assert.equal(repository.hasVote(releaseId, validator), true);
    assert.equal(repository.getValidatorNonce(validator), 1);
    assert.equal(repository.getRelease(releaseId)?.status, "QUARANTINED");
    const count = repository.listEvents().length;
    await indexer.syncOnce();
    assert.equal(repository.listEvents().length, count);
    block4Hash = `0x${"f".repeat(64)}`;
    includeStatus = false;
    await indexer.syncOnce();
    assert.equal(repository.getRelease(releaseId)?.status, "UNVERIFIED");
    assert.equal(repository.hasVote(releaseId, validator), true);
  } finally { repository.close(); }
});

test("rewind removes orphaned registration and makes its operation retryable", () => {
  const repository = new Repository(":memory:");
  try {
    const orphanId = "orphan-mcp@1.0.0";
    const txHash = `0x${"8".repeat(64)}`;
    repository.claimOperation(`register:${orphanId}`, "REGISTER_RELEASE", {
      releaseId: orphanId, artifactDigest: digest, toolSurfaceHash: toolHash,
    });
    repository.updatePendingOperation(`register:${orphanId}`, "SUBMITTED", txHash);
    repository.updatePendingOperation(`register:${orphanId}`, "COMPLETED", txHash);
    repository.applyIndexedRelease({ releaseId: orphanId, artifactDigest: digest,
      toolSurfaceHash: toolHash, txHash, blockNumber: 10, logIndex: 0 });
    assert.ok(repository.getRelease(orphanId));
    repository.rewindChainProjection(9);
    assert.equal(repository.getRelease(orphanId), undefined);
    assert.equal(repository.getPendingOperation(`register:${orphanId}`)?.status, "FAILED");
    assert.equal(repository.retryFailedOperation(`register:${orphanId}`), true);
    assert.doesNotThrow(() => repository.createRelease({ releaseId: orphanId,
      artifactDigest: digest, toolSurfaceHash: toolHash }));
  } finally { repository.close(); }
});
