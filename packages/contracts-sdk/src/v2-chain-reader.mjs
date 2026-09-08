import { Contract, JsonRpcProvider } from "ethers";
import { bytes32, exactReleaseIdentity } from "./v2-identity.mjs";
import { createReleaseRegistryV2 } from "./v2-registry.mjs";
import { checkedServiceUrl, v2RpcRequest, TransportUnavailableError } from "./transport.mjs";

const states = ["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"];
const hash = /^0x[0-9a-f]{64}$/i;
const FRESH_VIEW = Symbol("CHAIN_HEAD_ADVANCED");
export class V2ChainUnavailableError extends Error {
  constructor(failureKind = "TRUST_REJECTED") { super("STATUS_UNAVAILABLE"); this.name = "V2ChainUnavailableError"; this.failureKind = failureKind; }
}
const sameAttestation = (a, b) => ["reportRoot", "validatorSetVersion", "validFrom", "validUntil"].every(field => a[field] === b[field]);
const freshHead = (head, now = Date.now()) => Number.isFinite(head.timestamp * 1000) && head.timestamp * 1000 >= now - 30_000 && head.timestamp * 1000 <= now + 5_000;
function freshAllow(decision, head) {
  const now = Date.now();
  if (!freshHead(head, now)
    || Number(decision.validFrom) * 1000 > now || Number(decision.validUntil) * 1000 <= now) throw new Error("STALE_OR_EXPIRED_CHAIN_ALLOW");
}
async function completeReads(operations, decisionHead) {
  const results = await Promise.allSettled(operations), errors = results.filter(result => result.status === "rejected").map(result => result.reason);
  if (decisionHead && results[0].status === "fulfilled" && Number(results[0].value.status) === 1) freshAllow(results[0].value, decisionHead);
  // A concurrently received negative decision is not a pure connection outage,
  // even if another required proof query failed before identity assembly finished.
  if (errors.length && decisionHead && (results.slice(0, 2).some(result => result.status === "fulfilled" && Number(result.value.status) !== 1)
    || results[0].status === "fulfilled" && results[1].status === "fulfilled" && !sameAttestation(results[0].value, results[1].value))) throw new Error("PARTIAL_INCONSISTENT_VIEW");
  if (errors.length) throw errors.find(error => !(error instanceof TransportUnavailableError)) ?? errors[0];
  return results.map(result => result.value);
}
export function v2ChainReader(config) {
  const { registryContract, chainId, confirmations } = config, urls = [...config.rpcUrls];
  const timeoutMs = config.timeoutMs ?? 1500, allowedHttpHosts = [...(config.allowedHttpHosts ?? (process.env.CONTROL_V2_ALLOW_HTTP_HOSTS ?? "").split(",").filter(Boolean))];
  if (!urls.length || urls.length > 3 || !/^0x[0-9a-fA-F]{40}$/.test(registryContract) || !Number.isSafeInteger(chainId)
    || chainId <= 0 || !Number.isInteger(confirmations) || confirmations < 1) throw new Error("INVALID_V2_CHAIN_CONFIG");
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 5000) throw new Error("INVALID_V2_RPC_BUDGET");
  urls.forEach(url => checkedServiceUrl(url, allowedHttpHosts));
  const running = new Set(); let closed = false;
  const read = async (release, policy) => {
    if (closed) throw new V2ChainUnavailableError();
    release = { releaseId: release.releaseId, artifactDigest: release.artifactDigest, manifestDigest: release.manifestDigest, toolSurfaceHash: release.toolSurfaceHash };
    const policyHash = policy.policyHash;
    const controller = new AbortController(); running.add(controller);
    const deadline = performance.now() + timeoutMs, timer = setTimeout(() => controller.abort(new TransportUnavailableError()), timeoutMs);
    let freshViewRetries = 1, transportFailures = 0;
    try {
      for (const [index, url] of urls.entries()) {
        if (controller.signal.aborted) break;
        const remaining = deadline - performance.now(); if (remaining <= 0) break;
        // Reserve a share for every remaining endpoint within the same total
        // deadline; a stalled first endpoint must not prevent testing the rest.
        const providerBudget = Math.max(1, Math.floor(remaining / (urls.length - index))), providerDeadline = performance.now() + providerBudget, providerAbort = new AbortController();
        const providerTimer = setTimeout(() => providerAbort.abort(new TransportUnavailableError()), providerBudget);
        const signal = AbortSignal.any([controller.signal, providerAbort.signal]);
        // A post-query canonicality check must hit RPC, not ethers' 250ms cache.
        const provider = new JsonRpcProvider(v2RpcRequest(url, { timeoutMs: providerBudget, signal, allowedHttpHosts }), undefined, { batchMaxCount: 1, cacheTimeout: -1 });
        const registry = createReleaseRegistryV2(registryContract, provider);
        let negativeViewSeen = false, viewChangeSeen = false, staleHeadSeen = false;
        const checkedDecision = value => {
          if (!states[Number(value.status)]) throw new Error("INCONSISTENT_CHAIN_STATUS");
          if (Number(value.status) !== 1) negativeViewSeen = true;
          return value;
        };
        const checkedIdentity = identity => {
          if (!identity.exists || identity.artifactDigest !== bytes32(release.artifactDigest)
            || identity.manifestDigest !== bytes32(release.manifestDigest) || identity.toolSurfaceDigest !== bytes32(release.toolSurfaceHash)
            || exactReleaseIdentity({ toolId: identity.toolId, ...release }).releaseId !== release.releaseId) throw new Error("CHAIN_IDENTITY_MISMATCH");
          return identity;
        };
        try {
        for (;;) {
          viewChangeSeen = false;
          try {
            const network = await provider.getNetwork(); if (network.chainId !== BigInt(chainId)) throw new Error("CHAIN_ID_MISMATCH");
            const head = await provider.getBlock("latest");
            if (!head?.hash || !hash.test(head.hash) || /^0x0+$/.test(head.hash) || !Number.isSafeInteger(head.number) || head.number < confirmations) throw new Error("BLOCK_UNAVAILABLE");
            if (!freshHead(head)) staleHeadSeen = true;
            const confirmedNumber = head.number - confirmations + 1;
            const [latest, confirmed, identity, block, validatorAddress] = await completeReads([
              registry.getDecision(release.releaseId, policyHash, { blockTag: head.number }).then(checkedDecision),
              registry.getDecision(release.releaseId, policyHash, { blockTag: confirmedNumber }).then(checkedDecision),
              registry.releases(release.releaseId, { blockTag: head.number }).then(checkedIdentity), provider.getBlock(confirmedNumber).then(value => {
                if (!value?.hash || !hash.test(value.hash) || /^0x0+$/.test(value.hash) || value.number !== confirmedNumber) throw new Error("BLOCK_UNAVAILABLE"); return value;
              }),
              registry.validators({ blockTag: head.number }).then(value => { if (/^0x0+$/i.test(value)) throw new Error("VALIDATOR_SET_UNAVAILABLE"); return value; }),
            ], head);
            const validators = new Contract(validatorAddress, ["function version() view returns(uint32)"], provider);
            const version = Number(await validators.version({ blockTag: head.number }));
            if (!Number.isSafeInteger(version) || version < 1) throw new Error("VALIDATOR_SET_UNAVAILABLE");
            const currentStatus = states[Number(latest.status)], confirmedStatus = states[Number(confirmed.status)];
            if (!currentStatus || !confirmedStatus || (confirmedStatus === "REVOKED" && currentStatus !== "REVOKED")) throw new Error("INCONSISTENT_CHAIN_STATUS");
            let decision = latest, observed = head;
            // Optimistic denial wins. Allow needs the same confirmed/current attestation.
            if (currentStatus === "VERIFIED") {
              if (confirmedStatus !== "VERIFIED" || !sameAttestation(confirmed, latest) || Number(latest.validatorSetVersion) !== version)
                return { status: "UNVERIFIED", source: "EVM", unavailable: true };
              decision = confirmed; observed = block;
            }
            // A benign extension may get one complete fresh read, never an old-view ALLOW.
            // Reorgs, negative/inconsistent states and all other errors do not use this retry.
            const [afterHead, afterConfirmed] = await completeReads([provider.getBlock("latest").then(value => {
              if (value?.number !== head.number || value?.hash !== head.hash) viewChangeSeen = true; return value;
            }), provider.getBlock(confirmedNumber).then(value => {
              if (value?.hash !== block.hash || value?.number !== confirmedNumber) throw new Error("CHAIN_VIEW_CHANGED"); return value;
            })]);
            if (signal.aborted) throw signal.reason;
            if (afterHead?.number !== head.number || afterHead?.hash !== head.hash || afterConfirmed?.hash !== block.hash) {
              if (currentStatus === "VERIFIED" && Number.isSafeInteger(afterHead?.number) && afterHead.number > head.number
                && hash.test(afterHead.hash ?? "") && !/^0x0+$/.test(afterHead.hash) && afterConfirmed?.hash === block.hash)
                throw FRESH_VIEW;
              throw new Error("CHAIN_VIEW_CHANGED");
            }
            const result = { status: states[Number(decision.status)], source: "EVM", policyHash, reportRoot: decision.reportRoot,
              validFrom: new Date(Number(decision.validFrom) * 1000).toISOString(), validUntil: new Date(Number(decision.validUntil) * 1000).toISOString(),
              validatorSetVersion: version, chainId, registryContract, observedBlock: observed.number, blockHash: observed.hash,
              headBlock: head.number, headBlockHash: head.hash, headTimestamp: new Date(head.timestamp * 1000).toISOString() };
            if (signal.aborted) throw signal.reason;
            if (result.status === "VERIFIED") freshAllow(decision, head);
            // Timer callbacks may be delayed while synchronous decoding runs.
            // A late completed proof is rejected, not called a native I/O outage.
            if (performance.now() >= deadline || performance.now() >= providerDeadline) throw new V2ChainUnavailableError();
            return result;
          } catch (error) {
            if (closed || controller.signal.aborted && !(controller.signal.reason instanceof TransportUnavailableError)) throw new V2ChainUnavailableError();
            if (error === FRESH_VIEW) {
              if (freshViewRetries-- > 0 && !signal.aborted) continue;
              throw new V2ChainUnavailableError();
            }
            if (negativeViewSeen || viewChangeSeen || staleHeadSeen || !(error instanceof TransportUnavailableError)) throw new V2ChainUnavailableError();
            transportFailures++; break;
          }
        }
        } finally { clearTimeout(providerTimer); providerAbort.abort(); provider.destroy(); }
      }
      throw new V2ChainUnavailableError(!closed && transportFailures === urls.length ? "TRANSPORT_UNAVAILABLE" : "TRUST_REJECTED");
    } finally { clearTimeout(timer); controller.abort(); running.delete(controller); }
  };
  return Object.assign(read, { close: () => { closed = true; running.forEach(controller => controller.abort()); } });
}
