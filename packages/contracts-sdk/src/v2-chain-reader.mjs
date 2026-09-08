import { Contract, JsonRpcProvider } from "ethers";
import { bytes32, exactReleaseIdentity } from "./v2-identity.mjs";
import { createReleaseRegistryV2 } from "./v2-registry.mjs";
import { checkedServiceUrl, v2RpcRequest } from "./transport.mjs";

const states = ["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"];
const hash = /^0x[0-9a-f]{64}$/i;
export function v2ChainReader(config) {
  const { registryContract, chainId, confirmations } = config, urls = [...config.rpcUrls];
  const timeoutMs = config.timeoutMs ?? 1500, allowedHttpHosts = [...(config.allowedHttpHosts ?? (process.env.CONTROL_V2_ALLOW_HTTP_HOSTS ?? "").split(",").filter(Boolean))];
  if (!urls.length || urls.length > 3 || !/^0x[0-9a-fA-F]{40}$/.test(registryContract) || !Number.isSafeInteger(chainId)
    || chainId <= 0 || !Number.isInteger(confirmations) || confirmations < 1) throw new Error("INVALID_V2_CHAIN_CONFIG");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 5000) throw new Error("INVALID_V2_RPC_BUDGET");
  urls.forEach(url => checkedServiceUrl(url, allowedHttpHosts));
  const running = new Set(); let closed = false;
  const read = async (release, policy) => {
    if (closed) throw new Error("STATUS_UNAVAILABLE");
    release = { releaseId: release.releaseId, artifactDigest: release.artifactDigest, manifestDigest: release.manifestDigest, toolSurfaceHash: release.toolSurfaceHash };
    const policyHash = policy.policyHash;
    const controller = new AbortController(); running.add(controller);
    const timer = setTimeout(() => controller.abort(new Error("RPC_BUDGET_EXCEEDED")), timeoutMs);
    const readers = urls.map(url => {
      // A post-query canonicality check must hit RPC, not ethers' 250ms cache.
      const provider = new JsonRpcProvider(v2RpcRequest(url, { timeoutMs, signal: controller.signal, allowedHttpHosts }), undefined, { batchMaxCount: 1, cacheTimeout: -1 });
      return { provider, registry: createReleaseRegistryV2(registryContract, provider) };
    });
    try {
      for (const { provider, registry } of readers) {
        if (controller.signal.aborted) break;
        try {
          const network = await provider.getNetwork(); if (network.chainId !== BigInt(chainId)) throw new Error("CHAIN_ID_MISMATCH");
          const head = await provider.getBlock("latest");
          if (!head?.hash || !hash.test(head.hash) || !Number.isSafeInteger(head.number) || head.number < confirmations) throw new Error("BLOCK_UNAVAILABLE");
          const confirmedNumber = head.number - confirmations + 1;
          const [latest, confirmed, identity, block, validatorAddress] = await Promise.all([
            registry.getDecision(release.releaseId, policyHash, { blockTag: head.number }),
            registry.getDecision(release.releaseId, policyHash, { blockTag: confirmedNumber }),
            registry.releases(release.releaseId, { blockTag: head.number }), provider.getBlock(confirmedNumber),
            registry.validators({ blockTag: head.number }),
          ]);
          if (!identity.exists || identity.artifactDigest !== bytes32(release.artifactDigest)
            || identity.manifestDigest !== bytes32(release.manifestDigest) || identity.toolSurfaceDigest !== bytes32(release.toolSurfaceHash)
            || exactReleaseIdentity({ toolId: identity.toolId, ...release }).releaseId !== release.releaseId) throw new Error("CHAIN_IDENTITY_MISMATCH");
          if (!block?.hash || !hash.test(block.hash)) throw new Error("BLOCK_UNAVAILABLE");
          const validators = new Contract(validatorAddress, ["function version() view returns(uint32)"], provider);
          const version = Number(await validators.version({ blockTag: head.number }));
          if (!Number.isSafeInteger(version) || version < 1) throw new Error("VALIDATOR_SET_UNAVAILABLE");
          // Reject a moving/inconsistent view; do not certify results using a pre-query hash.
          const [afterHead, afterConfirmed] = await Promise.all([provider.getBlock("latest"), provider.getBlock(confirmedNumber)]);
          if (controller.signal.aborted || afterHead?.number !== head.number || afterHead?.hash !== head.hash || afterConfirmed?.hash !== block.hash) throw new Error("CHAIN_VIEW_CHANGED");
          const currentStatus = states[Number(latest.status)], confirmedStatus = states[Number(confirmed.status)];
          if (!currentStatus || !confirmedStatus || (confirmedStatus === "REVOKED" && currentStatus !== "REVOKED")) throw new Error("INCONSISTENT_CHAIN_STATUS");
          let decision = latest, observed = head;
          // Optimistic denial wins. Allow needs the same confirmed/current attestation.
          if (currentStatus === "VERIFIED") {
            if (confirmedStatus !== "VERIFIED" || confirmed.reportRoot !== latest.reportRoot || confirmed.validatorSetVersion !== latest.validatorSetVersion
              || confirmed.validFrom !== latest.validFrom || confirmed.validUntil !== latest.validUntil || Number(latest.validatorSetVersion) !== version)
              return { status: "UNVERIFIED", source: "EVM", unavailable: true };
            decision = confirmed; observed = block;
          }
          return { status: states[Number(decision.status)], source: "EVM", policyHash, reportRoot: decision.reportRoot,
            validFrom: new Date(Number(decision.validFrom) * 1000).toISOString(), validUntil: new Date(Number(decision.validUntil) * 1000).toISOString(),
            validatorSetVersion: version, chainId, registryContract, observedBlock: observed.number, blockHash: observed.hash,
            headBlock: head.number, headBlockHash: head.hash, headTimestamp: new Date(head.timestamp * 1000).toISOString() };
        } catch { /* Configured RPC alternatives share one deadline; none may use a stale allow. */ }
      }
      throw new Error("STATUS_UNAVAILABLE");
    } finally { clearTimeout(timer); controller.abort(); running.delete(controller); readers.forEach(({ provider }) => provider.destroy()); }
  };
  return Object.assign(read, { close: () => { closed = true; running.forEach(controller => controller.abort()); } });
}
