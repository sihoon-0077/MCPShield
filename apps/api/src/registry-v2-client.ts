import { Contract, FetchRequest, JsonRpcProvider } from "ethers";
import { bytes32, createReleaseRegistryV2 } from "../../../packages/contracts-sdk/src/v2.js";

const states = ["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"];
export function v2ChainReader(config: { rpcUrls: string[]; registryContract: string; chainId: number; confirmations: number }) {
  if (!config.rpcUrls.length || !/^0x[0-9a-fA-F]{40}$/.test(config.registryContract) || !Number.isSafeInteger(config.chainId)
    || config.chainId <= 0 || !Number.isInteger(config.confirmations) || config.confirmations < 1) throw new Error("INVALID_V2_CHAIN_CONFIG");
  const readers = config.rpcUrls.map((url) => {
    const transport = new FetchRequest(url); transport.timeout = 2500;
    const provider = new JsonRpcProvider(transport, undefined, { batchMaxCount: 1 });
    return { provider, registry: createReleaseRegistryV2(config.registryContract, provider) };
  });
  const read = async (release: Record<string, any>, policy: Record<string, any>) => {
    for (const { provider, registry } of readers) {
      try {
        const network = await provider.getNetwork(); if (network.chainId !== BigInt(config.chainId)) throw new Error("CHAIN_ID_MISMATCH");
        const head = await provider.getBlock("latest"); if (!head?.hash) throw new Error("BLOCK_UNAVAILABLE");
        const confirmedNumber = Math.max(0, head.number - config.confirmations + 1);
        const [latest, confirmed, identity, block, validatorAddress] = await Promise.all([
          registry.getDecision(release.releaseId, policy.policyHash, { blockTag: head.number }),
          registry.getDecision(release.releaseId, policy.policyHash, { blockTag: confirmedNumber }),
          registry.releases(release.releaseId, { blockTag: head.number }), provider.getBlock(confirmedNumber), registry.validators(),
        ]);
        if (!identity.exists || identity.artifactDigest !== bytes32(release.artifactDigest)
          || identity.manifestDigest !== bytes32(release.manifestDigest) || identity.toolSurfaceDigest !== bytes32(release.toolSurfaceHash)) throw new Error("CHAIN_IDENTITY_MISMATCH");
        const validators = new Contract(validatorAddress, ["function version() view returns(uint32)"], provider);
        const version = Number(await validators.version({ blockTag: head.number }));
        // Optimistic deny takes precedence; ALLOW requires confirmed and current agreement.
        const currentStatus = states[Number(latest.status)], confirmedStatus = states[Number(confirmed.status)];
        let decision = latest, observed = head;
        if (currentStatus === "VERIFIED") {
          if (confirmedStatus !== "VERIFIED" || confirmed.reportRoot !== latest.reportRoot || confirmed.validatorSetVersion !== latest.validatorSetVersion
            || confirmed.validUntil !== latest.validUntil || !block?.hash) return { status: "UNVERIFIED", source: "EVM", unavailable: true };
          decision = confirmed; observed = block;
        }
        const status = states[Number(decision.status)]; if (!status) throw new Error("UNKNOWN_CHAIN_STATUS");
        return { status, source: "EVM", policyHash: policy.policyHash, reportRoot: decision.reportRoot,
          validFrom: new Date(Number(decision.validFrom) * 1000).toISOString(), validUntil: new Date(Number(decision.validUntil) * 1000).toISOString(),
          validatorSetVersion: version, chainId: config.chainId, registryContract: config.registryContract,
          observedBlock: observed.number, blockHash: observed.hash };
      } catch { /* Try another configured RPC. No stale allow fallback exists in the API. */ }
    }
    throw new Error("STATUS_UNAVAILABLE");
  };
  return Object.assign(read, { close: () => readers.forEach(({ provider }) => provider.destroy()) });
}
