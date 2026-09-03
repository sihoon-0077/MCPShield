import { Interface, type Log } from "ethers";
import { releaseRegistryAbi, statusFromChain } from "../../../packages/contracts-sdk/src/index.js";
import type { ValidatorDecision } from "../../../packages/protocol/api/types.js";
import { Repository } from "../../api/src/repository.js";

interface ProviderPort {
  getNetwork(): Promise<{ chainId: bigint }>;
  getBlockNumber(): Promise<number>;
  getBlock(blockNumber: number): Promise<{ hash?: string | null } | null>;
  getLogs(filter: { address: string; fromBlock: number; toBlock: number }): Promise<Log[]>;
}

export class ChainIndexer {
  private readonly abi = new Interface(releaseRegistryAbi);
  constructor(private readonly provider: ProviderPort, private readonly registry: any,
    private readonly repository: Repository, private readonly registryAddress: string,
    private readonly deploymentBlock: number, private readonly confirmationDepth: number,
    private readonly rewindBlocks: number) {}

  private async releaseForKey(key: string) {
    const item = await this.registry.getRelease(key);
    return { releaseId: item.releaseId as string,
      artifactDigest: `sha256:${String(item.artifactDigest).slice(2).toLowerCase()}`,
      toolSurfaceHash: String(item.toolSurfaceHash).toLowerCase(), status: statusFromChain(item.status) };
  }

  private async processLog(log: Log) {
    const parsed = this.abi.parseLog(log);
    if (!parsed) return;
    if (parsed.name === "ReleaseRegistered") {
      this.repository.applyIndexedRelease({ releaseId: parsed.args.releaseId,
        artifactDigest: `sha256:${String(parsed.args.artifactDigest).slice(2).toLowerCase()}`,
        toolSurfaceHash: String(parsed.args.toolSurfaceHash).toLowerCase(),
        txHash: log.transactionHash, blockNumber: log.blockNumber, logIndex: log.index });
      return;
    }
    const release = await this.releaseForKey(parsed.args.releaseKey);
    if (parsed.name === "VoteSubmitted") {
      const validatorAddress = String(parsed.args.validator).toLowerCase();
      const decisions: ValidatorDecision[] = ["PASS", "FAIL", "ABSTAIN"];
      this.repository.applyIndexedVote({ releaseId: release.releaseId, validatorAddress,
        decision: decisions[Number(parsed.args.decision)],
        evidenceHash: String(parsed.args.evidenceHash).toLowerCase(), nonce: Number(parsed.args.nonce),
        chainNonce: Number(await this.registry.nonces(validatorAddress)), txHash: log.transactionHash,
        blockNumber: log.blockNumber, logIndex: log.index });
    } else if (parsed.name === "StatusChanged") {
      this.repository.applyIndexedStatus({ releaseId: release.releaseId,
        status: statusFromChain(parsed.args.newStatus), txHash: log.transactionHash,
        blockNumber: log.blockNumber, logIndex: log.index });
    }
  }

  async syncOnce() {
    const chainId = (await this.provider.getNetwork()).chainId.toString();
    const checkpointName = `release-registry:${chainId}:${this.registryAddress.toLowerCase()}`;
    let checkpoint = this.repository.getCheckpoint(checkpointName);
    if (checkpoint && checkpoint.blockNumber >= 0) {
      const canonicalBlock = await this.provider.getBlock(checkpoint.blockNumber);
      if (!canonicalBlock?.hash || canonicalBlock.hash.toLowerCase() !== checkpoint.blockHash.toLowerCase()) {
        const rewindTo = Math.max(this.deploymentBlock - 1, checkpoint.blockNumber - this.rewindBlocks);
        this.repository.rewindChainProjection(rewindTo);
        const rewindBlock = rewindTo >= 0 ? await this.provider.getBlock(rewindTo) : null;
        this.repository.setCheckpoint(checkpointName, rewindTo, rewindBlock?.hash ?? "GENESIS");
        checkpoint = { blockNumber: rewindTo, blockHash: rewindBlock?.hash ?? "GENESIS" };
      }
    }
    const latest = await this.provider.getBlockNumber();
    const safeLatest = latest - Math.max(0, this.confirmationDepth);
    let from = (checkpoint?.blockNumber ?? this.deploymentBlock - 1) + 1;
    while (from <= safeLatest) {
      const to = Math.min(from + 999, safeLatest);
      const logs = await this.provider.getLogs({ address: this.registryAddress, fromBlock: from, toBlock: to });
      for (const log of logs) await this.processLog(log);
      const block = await this.provider.getBlock(to);
      if (!block?.hash) throw new Error(`BLOCK_HASH_UNAVAILABLE:${to}`);
      this.repository.setCheckpoint(checkpointName, to, block.hash);
      from = to + 1;
    }
  }
}
