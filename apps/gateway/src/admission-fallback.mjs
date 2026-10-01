import { createHash, createPublicKey } from "node:crypto";
import { checkedServiceUrl } from "../../../packages/contracts-sdk/src/transport.mjs";
import { v2ChainReader } from "../../../packages/contracts-sdk/src/v2-chain-reader.mjs";

const digest = /^sha256:[a-f0-9]{64}$/, id = /^0x[a-f0-9]{64}$/;
const fields = ["schemaVersion", "releaseId", "artifactDigest", "manifestDigest", "toolSurfaceHash", "chainId", "registryContract", "status", "observedBlock", "blockHash", "checkedAt"].sort().join();
const fail = code => { throw new Error(code); };
let tokens = 4, replenished = performance.now();
// ponytail: one process-wide bucket, burst 4 and 2 admission reads/second.
// Multiple independent wrappers require an RPC service quota, not a bigger local map.
function takeRpcToken() {
  const now = performance.now(); tokens = Math.min(4, tokens + (now - replenished) / 500); replenished = now;
  if (tokens < 1) fail("DIRECT_RPC_RATE_LIMITED"); tokens--;
}

export function fallbackConfiguration({ indexer, rpc }, { chainId, registryContract }) {
  if (indexer === undefined && [process.env.MCPSHIELD_ORG_INDEXER_URL, process.env.MCPSHIELD_ORG_INDEXER_TOKEN, process.env.MCPSHIELD_ORG_INDEXER_KEY_ID, process.env.MCPSHIELD_ORG_INDEXER_PUBLIC_KEY].some(Boolean))
    indexer = { url: process.env.MCPSHIELD_ORG_INDEXER_URL, token: process.env.MCPSHIELD_ORG_INDEXER_TOKEN, keyId: process.env.MCPSHIELD_ORG_INDEXER_KEY_ID, publicKey: process.env.MCPSHIELD_ORG_INDEXER_PUBLIC_KEY?.replace(/\\n/g, "\n") };
  if (indexer) {
    const url = checkedServiceUrl(indexer.url, (process.env.MCPSHIELD_API_HTTP_HOSTS ?? "").split(",").filter(Boolean));
    if (url.href.length > 2048 || url.pathname !== "/" || url.search || typeof indexer.token !== "string" || !/^[\x21-\x7e]{16,2048}$/.test(indexer.token)
      || typeof indexer.keyId !== "string" || !/^[\x21-\x7e]{1,128}$/.test(indexer.keyId) || !indexer.publicKey
      || createPublicKey(indexer.publicKey).asymmetricKeyType !== "ed25519") fail("INVALID_ORG_INDEXER_TRUST");
    indexer = { url: url.origin, token: indexer.token, keyId: indexer.keyId, publicKey: indexer.publicKey };
  }
  if (rpc === undefined && process.env.MCPSHIELD_RPC_URLS) rpc = {
    rpcUrls: process.env.MCPSHIELD_RPC_URLS.split(",").map(value => value.trim()).filter(Boolean),
    confirmations: Number(process.env.MCPSHIELD_RPC_CONFIRMATIONS ?? 2), timeoutMs: Number(process.env.MCPSHIELD_RPC_TIMEOUT_MS ?? 1500),
    allowedHttpHosts: (process.env.MCPSHIELD_RPC_HTTP_HOSTS ?? "").split(",").map(value => value.trim()).filter(Boolean),
  };
  if (rpc) {
    rpc = { rpcUrls: Array.isArray(rpc.rpcUrls) ? [...rpc.rpcUrls] : rpc.rpcUrls, confirmations: rpc.confirmations ?? 2, timeoutMs: rpc.timeoutMs ?? 1500, allowedHttpHosts: [...(rpc.allowedHttpHosts ?? [])], chainId, registryContract };
    if (!Number.isSafeInteger(rpc.timeoutMs) || rpc.timeoutMs < 100 || rpc.timeoutMs > 1500) fail("DIRECT_RPC_TOTAL_BUDGET_INVALID");
    const checked = v2ChainReader(rpc); checked.close(); // Validate operator configuration before sending any credential.
  }
  return { indexer, rpc, fingerprint: createHash("sha256").update(JSON.stringify({ indexer, rpc })).digest("hex") };
}

export function rpcRevocationRecord(identity, state, now) {
  return { schemaVersion: "mcpshield.rpc-revocation.v1", releaseId: identity.releaseId, artifactDigest: identity.artifactDigest, manifestDigest: identity.manifestDigest,
    toolSurfaceHash: identity.toolSurfaceHash, chainId: state.chainId, registryContract: state.registryContract.toLowerCase(), status: "REVOKED",
    observedBlock: state.observedBlock, blockHash: state.blockHash, checkedAt: new Date(now).toISOString() };
}
export function validateRpcRevocation(record, { identity, chainId, registryContract }) {
  if (!record || Object.keys(record).sort().join() !== fields || record.schemaVersion !== "mcpshield.rpc-revocation.v1" || record.status !== "REVOKED"
    || record.releaseId !== identity.releaseId || record.artifactDigest !== identity.artifactDigest || record.toolSurfaceHash !== identity.toolSurfaceHash
    || !digest.test(record.manifestDigest) || identity.manifestDigest && record.manifestDigest !== identity.manifestDigest
    || record.chainId !== chainId || record.registryContract !== registryContract?.toLowerCase() || !Number.isSafeInteger(record.observedBlock) || record.observedBlock < 1
    || !id.test(record.blockHash) || /^0x0+$/.test(record.blockHash) || !Number.isFinite(Date.parse(record.checkedAt))) fail("INVALID_LOCAL_RPC_REVOCATION");
  // This is an unsigned local denial marker, not a reusable chain proof or an ALLOW credential.
  return record;
}

export async function directRpcAdmission(identity, context, rpc, now = Date.now) {
  if (!["READ_PUBLIC", "READ_PRIVATE"].includes(context.operationClass)) fail("DIRECT_RPC_HIGH_RISK_NOT_APPROVED");
  if (!digest.test(identity.manifestDigest)) fail("DIRECT_RPC_COMPLETE_LOCAL_IDENTITY_REQUIRED");
  takeRpcToken();
  const read = v2ChainReader(rpc);
  let state;
  try { state = await read(identity, { policyHash: context.policyHash }); } finally { read.close(); }
  const time = now();
  if (state.unavailable || state.source !== "EVM" || state.chainId !== context.chainId || state.registryContract?.toLowerCase() !== context.registryContract.toLowerCase()
    || state.policyHash !== context.policyHash || state.validatorSetVersion !== context.validatorSetVersion || !id.test(state.blockHash) || /^0x0+$/.test(state.blockHash)
    || !Number.isSafeInteger(state.observedBlock) || state.observedBlock < 1)
    fail("DIRECT_RPC_STATUS_UNAVAILABLE");
  const allow = state.status === "VERIFIED";
  if (allow && (!id.test(state.reportRoot) || /^0x0+$/.test(state.reportRoot) || !Number.isFinite(Date.parse(state.validFrom)) || !Number.isFinite(Date.parse(state.validUntil)) || Date.parse(state.validFrom) > time || Date.parse(state.validUntil) <= time)) fail("DIRECT_RPC_ATTESTATION_EXPIRED");
  return { state, snapshot: { releaseId: identity.releaseId, decision: allow ? "ALLOW" : "BLOCK", status: state.status, reasonCode: `RELEASE_${state.status}`,
    reportUrl: `/v1/releases/${identity.releaseId}`, issuedAt: new Date(time).toISOString(), expiresAt: new Date(allow
      ? Math.min(time + 30000, Date.parse(state.validUntil), Date.parse(state.headTimestamp) + 30000) : time + 30000).toISOString(), policyHash: context.policyHash } };
}
