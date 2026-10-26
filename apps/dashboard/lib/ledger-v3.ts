// Server-only, read-only view of ReleaseRegistryV3 straight from chain (ADR-008). Nothing here trusts the
// operator API. The transaction list is only a pointer: every receipt is fetched from chain, must be a
// successful call to this registry or its policy registry, and only logs emitted by the registry are used.
// Current state comes from contract views, and each company's admission is computed by the Gateway's own
// direct-RPC reader against its own RPC URL. (Public Base RPCs cap eth_getLogs at 200 blocks, so the page
// does not scan history.)
import { Contract, JsonRpcProvider } from "ethers";
import { createReleaseRegistryV3 } from "../../../packages/contracts-sdk/src/v3-registry.mjs";
import { v2RpcRequest } from "../../../packages/contracts-sdk/src/transport.mjs";
// @ts-expect-error Gateway direct-RPC admission is shared ESM JavaScript.
import { directRpcAdmission } from "../../gateway/src/admission-fallback.mjs";
import deployment from "../../../deployments/base-sepolia-v3.json";
import demoRecord from "../../../benchmarks/results/base-sepolia-v3-demo-2026-10-26/transactions.json";

export const STATUS = ["UNVERIFIED", "VERIFIED", "QUARANTINED", "REVOKED", "EXPIRED"] as const;
export const VERDICT = ["PASS", "FAIL", "ABSTAIN"] as const;
export const OUTCOME = ["OPEN", "APPROVED", "REJECTED", "SPLIT"] as const;

export interface LedgerConfig {
  rpcUrl: string; chainId: number; registry: string; policyRegistry: string; validators: string[];
  txHashes: string[]; names?: Record<string, string>; explorer?: string; companies: { name: string; rpcUrl: string }[]; allowedHttpHosts?: string[];
}
export interface LedgerVote { validator: string; label: string; verdict: string; evidenceHash: string; afterDecision: boolean; txHash: string; block: number }
export interface LedgerRound { roundId: string; validFrom: number; validUntil: number; outcome: string; approvals: number; rejections: number; abstentions: number; live: boolean; votes: LedgerVote[] }
export interface LedgerEvent { kind: string; detail: string; txHash: string; block: number; actor?: string }
export interface LedgerRelease {
  releaseId: string; name: string | null; toolId: string; artifactDigest: string; manifestDigest: string; toolSurfaceDigest: string;
  status: string; needsReview: boolean; liveRoundId: string; rounds: LedgerRound[]; events: LedgerEvent[];
  admission: { company: string; decision: string; reasonCode: string; observedBlock?: number; error?: string }[];
}
export interface Ledger { config: Omit<LedgerConfig, "companies"> & { companies: string[] }; policyHash: string | null; head: number; readAt: string; releases: LedgerRelease[] }

const short = (value: string) => `${value.slice(0, 10)}…${value.slice(-4)}`;

export function defaultLedgerConfig(env: Record<string, string | undefined> = process.env): LedgerConfig {
  const rpcUrl = env.MCPSHIELD_V3_RPC_URL ?? "https://sepolia.base.org";
  return { rpcUrl, chainId: Number(env.MCPSHIELD_V3_CHAIN_ID ?? deployment.chainId), registry: env.MCPSHIELD_V3_REGISTRY ?? deployment.releaseRegistry.address,
    policyRegistry: env.MCPSHIELD_V3_POLICY_REGISTRY ?? deployment.policyRegistry.address, validators: deployment.validatorAddresses,
    txHashes: [...demoRecord.steps.map((step: any) => step.txHash), ...(env.MCPSHIELD_V3_TX_HASHES ?? "").split(",").filter(Boolean)],
    // Display names only; the identity shown next to them is read from chain.
    names: Object.fromEntries(Object.values(demoRecord.releases).map((r: any) => [r.releaseId, r.fixture.split("/").at(-1)])), explorer: env.MCPSHIELD_V3_EXPLORER ?? "https://sepolia.basescan.org",
    // Two companies run their own Gateways with their own RPC URL; neither asks the operator.
    companies: [{ name: "A사", rpcUrl: env.MCPSHIELD_V3_RPC_A ?? rpcUrl }, { name: "B사", rpcUrl: env.MCPSHIELD_V3_RPC_B ?? rpcUrl }],
    allowedHttpHosts: (env.MCPSHIELD_V3_HTTP_HOSTS ?? "").split(",").filter(Boolean) };
}

export async function readLedger(config: LedgerConfig = defaultLedgerConfig()): Promise<Ledger> {
  const provider = new JsonRpcProvider(v2RpcRequest(config.rpcUrl, { allowedHttpHosts: config.allowedHttpHosts }), config.chainId, { staticNetwork: true, batchMaxCount: 1 });
  try {
    const registry: any = createReleaseRegistryV3(config.registry, provider);
    const policies = new Contract(config.policyRegistry, ["event PolicyPublished(bytes32 indexed policyHash, bytes32 documentDigest)",
      "function active(bytes32) view returns (bool)"], provider);
    const head = await provider.getBlockNumber();
    const logs: any[] = [];
    let policyHash: string | null = null;
    for (const hash of [...new Set(config.txHashes)].filter((h) => /^0x[0-9a-fA-F]{64}$/.test(h))) {
      const receipt = await provider.getTransactionReceipt(hash);
      if (!receipt || receipt.status !== 1 || ![config.registry, config.policyRegistry].some((a) => a.toLowerCase() === receipt.to?.toLowerCase())) continue;
      for (const log of receipt.logs) {
        if (log.address.toLowerCase() === config.policyRegistry.toLowerCase()) {
          const parsed = policies.interface.parseLog(log);
          if (parsed?.name === "PolicyPublished" && await policies.active(parsed.args.policyHash)) policyHash = parsed.args.policyHash;
          continue;
        }
        if (log.address.toLowerCase() !== config.registry.toLowerCase()) continue;
        const parsed = registry.interface.parseLog(log);
        if (parsed) logs.push({ name: parsed.name, args: parsed.args, transactionHash: receipt.hash, blockNumber: receipt.blockNumber });
      }
    }
    const label = (address: string) => ["A", "B", "C"][config.validators.findIndex((v) => v.toLowerCase() === address.toLowerCase())] ?? short(address);
    const named = (name: string) => logs.filter((l) => l.name === name);
    const [registered, votes, quarantines, revocations, reviews] = ["ReleaseRegistered", "VoteRecorded", "ReleaseQuarantined", "ReleaseRevoked", "ReviewRequired"].map(named);
    const releases: LedgerRelease[] = [];
    for (const log of registered) {
      const releaseId: string = log.args.releaseId;
      const identity = await registry.releases(releaseId);
      const roundIds = [...new Set(votes.filter((v) => v.args.releaseId === releaseId).map((v) => v.args.roundId as string))];
      const live = policyHash ? await registry.currentRound(releaseId, policyHash) : null;
      const rounds: LedgerRound[] = [];
      for (const roundId of roundIds) {
        const r = await registry.getRound(roundId);
        rounds.push({ roundId, validFrom: Number(r.validFrom), validUntil: Number(r.validUntil), outcome: OUTCOME[Number(r.outcome)], approvals: Number(r.approvals),
          rejections: Number(r.rejections), abstentions: Number(r.abstentions), live: roundId === live,
          votes: votes.filter((v) => v.args.roundId === roundId).map((v) => ({ validator: v.args.validator, label: label(v.args.validator), verdict: VERDICT[Number(v.args.verdict)],
            evidenceHash: v.args.evidenceHash, afterDecision: v.args.afterDecision, txHash: v.transactionHash, block: v.blockNumber })) });
      }
      const events: LedgerEvent[] = [
        { kind: "REGISTERED", detail: "운영사가 릴리스 신원(배포본·매니페스트·도구 목록 해시)을 등록", txHash: log.transactionHash, block: log.blockNumber },
        ...votes.filter((v) => v.args.releaseId === releaseId).map((v) => ({ kind: "VOTE", actor: label(v.args.validator),
          detail: `검증자 ${label(v.args.validator)} ${VERDICT[Number(v.args.verdict)]}${v.args.afterDecision ? " (결정 후 기록된 반대·추가 표)" : ""}`, txHash: v.transactionHash, block: v.blockNumber })),
        ...quarantines.filter((q) => q.args.releaseId === releaseId).map((q) => ({ kind: "QUARANTINE", actor: label(q.args.validator),
          detail: `검증자 ${label(q.args.validator)}가 자기 지갑으로 긴급 격리`, txHash: q.transactionHash, block: q.blockNumber })),
        ...revocations.filter((r) => r.args.releaseId === releaseId).map((r) => ({ kind: "REVOKED", detail: "FAIL 2표로 폐기 (되돌릴 수 없음)", txHash: r.transactionHash, block: r.blockNumber })),
        ...reviews.filter((r) => r.args.releaseId === releaseId).map((r) => ({ kind: "REVIEW", detail: "표가 갈려 사람 검토 필요", txHash: r.transactionHash, block: r.blockNumber })),
      ].sort((a, b) => a.block - b.block);
      const decision = policyHash ? await registry.getDecision(releaseId, policyHash) : null;
      releases.push({ releaseId, name: config.names?.[releaseId] ?? null, toolId: identity.toolId, artifactDigest: identity.artifactDigest, manifestDigest: identity.manifestDigest, toolSurfaceDigest: identity.toolSurfaceDigest,
        status: decision ? STATUS[Number(decision.status)] : "UNVERIFIED", needsReview: policyHash ? await registry.needsReview(releaseId, policyHash) : false,
        liveRoundId: live ?? "", rounds, events, admission: [] });
    }
    if (policyHash) {
      const version = Number(await new Contract(await registry.validators(), ["function version() view returns(uint32)"], provider).version());
      for (const release of releases) for (const company of config.companies) {
        // The Gateway's own reader: fresh head, confirmations, identity re-check, VERIFIED-only allow.
        const identity = { releaseId: release.releaseId, artifactDigest: `sha256:${release.artifactDigest.slice(2)}`, manifestDigest: `sha256:${release.manifestDigest.slice(2)}`,
          toolSurfaceHash: release.toolSurfaceDigest };
        // The Gateway allows two direct-RPC admission reads per second per process.
        await new Promise((resolve) => setTimeout(resolve, 550));
        try {
          const { snapshot, state } = await directRpcAdmission(identity, { operationClass: "READ_PUBLIC", policyHash, chainId: config.chainId, registryContract: config.registry,
            validatorSetVersion: version }, { rpcUrls: [company.rpcUrl], confirmations: 2, timeoutMs: 3000, chainId: config.chainId, registryContract: config.registry,
            allowedHttpHosts: config.allowedHttpHosts ?? [] });
          release.admission.push({ company: company.name, decision: snapshot.decision, reasonCode: snapshot.reasonCode, observedBlock: state.observedBlock });
        } catch (error: any) {
          // Fail closed, exactly like the Gateway: no answer is a block.
          release.admission.push({ company: company.name, decision: "BLOCK", reasonCode: "STATUS_UNAVAILABLE", error: /^[A-Z_]+$/.test(error?.message ?? "") ? error.message : "READ_FAILED" });
        }
      }
    }
    const { companies, ...rest } = config;
    return { config: { ...rest, companies: companies.map((c) => c.name) }, policyHash, head, readAt: new Date().toISOString(), releases };
  } finally { provider.destroy(); }
}
