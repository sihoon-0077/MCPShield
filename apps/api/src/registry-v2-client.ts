import { Contract, JsonRpcProvider } from "ethers";
import { bytes32, createReleaseRegistryV2 } from "../../../packages/contracts-sdk/src/v2.js";
import { checkedServiceUrl, v2RpcRequest } from "../../../packages/contracts-sdk/src/transport.js";

const states = ["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"];
export function v2ChainReader(config: { rpcUrls: string[]; registryContract: string; chainId: number; confirmations: number; timeoutMs?: number; allowedHttpHosts?: string[] }) {
  const timeoutMs = config.timeoutMs ?? 1500, allowedHttpHosts = config.allowedHttpHosts ?? (process.env.CONTROL_V2_ALLOW_HTTP_HOSTS ?? "").split(",").filter(Boolean);
  if (!config.rpcUrls.length || config.rpcUrls.length > 3 || !/^0x[0-9a-fA-F]{40}$/.test(config.registryContract) || !Number.isSafeInteger(config.chainId)
    || config.chainId <= 0 || !Number.isInteger(config.confirmations) || config.confirmations < 1) throw new Error("INVALID_V2_CHAIN_CONFIG");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 5000) throw new Error("INVALID_V2_RPC_BUDGET");
  config.rpcUrls.forEach((url) => checkedServiceUrl(url, allowedHttpHosts));
  const running = new Set<AbortController>(); let closed = false;
  const read = async (release: Record<string, any>, policy: Record<string, any>) => {
    if (closed) throw new Error("STATUS_UNAVAILABLE");
    const controller = new AbortController(); running.add(controller);
    const timer = setTimeout(() => controller.abort(new Error("RPC_BUDGET_EXCEEDED")), timeoutMs);
    const readers = config.rpcUrls.map((url) => {
      const provider = new JsonRpcProvider(v2RpcRequest(url, { timeoutMs, signal: controller.signal, allowedHttpHosts }), undefined, { batchMaxCount: 1 });
      return { provider, registry: createReleaseRegistryV2(config.registryContract, provider) };
    });
    try {
    for (const { provider, registry } of readers) {
      if (controller.signal.aborted) break;
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
    } finally { clearTimeout(timer); controller.abort(); running.delete(controller); readers.forEach(({ provider }) => provider.destroy()); }
  };
  return Object.assign(read, { close: () => { closed = true; running.forEach((controller) => controller.abort()); } });
}
