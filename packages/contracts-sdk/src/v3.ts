import { Contract, type ContractRunner } from "ethers";
import { releaseRegistryV2Abi } from "./v2-registry.mjs";

export { bytes32, exactReleaseIdentity } from "./v2-identity.mjs";
// Quarantine signatures keep the V2 shape; only the domain version differs.
export { quarantineV2Types as quarantineV3Types } from "./v2.js";

/** ADR-008: each validator signs its own evidenceHash instead of a shared reportRoot. */
export const attestationV3Types = { Attestation: [
  { name: "releaseId", type: "bytes32" }, { name: "artifactDigest", type: "bytes32" },
  { name: "manifestDigest", type: "bytes32" }, { name: "toolSurfaceDigest", type: "bytes32" },
  { name: "policyHash", type: "bytes32" }, { name: "evidenceHash", type: "bytes32" },
  { name: "verdict", type: "uint8" }, { name: "validFrom", type: "uint64" },
  { name: "validUntil", type: "uint64" }, { name: "validatorSetVersion", type: "uint32" },
  { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" },
] };
export const attestationV3Domain = (chainId: number | bigint, verifyingContract: string) => ({
  name: "MCPShieldReleaseRegistry", version: "3", chainId, verifyingContract,
});
export const ROUND_OUTCOMES = ["OPEN", "APPROVED", "REJECTED", "SPLIT"] as const;

// The V2 read surface (releases, getDecision, validators, policies, nonces, quarantine*) is unchanged;
// V2-only write and event entries are left out so a V3 client cannot encode a V2 attestation by mistake.
const sharedV2 = releaseRegistryV2Abi.filter((entry) => !/submitAttestation|usedDigest|AttestationAccepted/.test(entry));
export const releaseRegistryV3Abi = [
  ...sharedV2,
  "function submitAttestation((bytes32 releaseId,bytes32 artifactDigest,bytes32 manifestDigest,bytes32 toolSurfaceDigest,bytes32 policyHash,bytes32 evidenceHash,uint8 verdict,uint64 validFrom,uint64 validUntil,uint32 validatorSetVersion,uint256 nonce,uint256 deadline) a,bytes signature)",
  "function roundIdOf(bytes32 releaseId,bytes32 policyHash,uint64 validFrom,uint64 validUntil,uint32 validatorSetVersion) pure returns (bytes32)",
  "function currentRound(bytes32 releaseId,bytes32 policyHash) view returns (bytes32)",
  "function getRound(bytes32 roundId) view returns ((bytes32 releaseId,bytes32 policyHash,uint64 validFrom,uint64 validUntil,uint32 validatorSetVersion,uint8 approvals,uint8 rejections,uint8 abstentions,uint8 outcome,uint64 openedAt,uint64 decidedAt))",
  "function getVote(bytes32 roundId,address validator) view returns ((bool cast,uint8 verdict,bytes32 evidenceHash))",
  "function needsReview(bytes32 releaseId,bytes32 policyHash) view returns (bool)",
  "function revoked(bytes32) view returns (bool)",
  "function revokedRound(bytes32) view returns (bytes32)",
  "function revokedBytes(bytes32) view returns (bool)",
  "function quarantinedAt(bytes32) view returns (uint64)",
  "function quarantineUntil(bytes32) view returns (uint64)",
  "function lastQuarantineAt(bytes32,address) view returns (uint64)",
  "event RoundOpened(bytes32 indexed roundId,bytes32 indexed releaseId,bytes32 indexed policyHash,uint64 validFrom,uint64 validUntil,uint32 validatorSetVersion)",
  "event VoteRecorded(bytes32 indexed roundId,bytes32 indexed releaseId,address indexed validator,uint8 verdict,bytes32 evidenceHash,bool afterDecision)",
  "event RoundDecided(bytes32 indexed roundId,bytes32 indexed releaseId,bytes32 indexed policyHash,uint8 outcome,uint8 approvals,uint8 rejections,uint8 abstentions)",
  "event ReviewRequired(bytes32 indexed releaseId,bytes32 indexed policyHash,bytes32 indexed roundId)",
  "event ReleaseRevoked(bytes32 indexed releaseId,bytes32 indexed policyHash,bytes32 indexed roundId)",
  "event BytesRevoked(bytes32 indexed bytesKey,bytes32 artifactDigest,bytes32 manifestDigest,bytes32 toolSurfaceDigest,bytes32 indexed roundId)",
  "event ReleaseQuarantined(bytes32 indexed releaseId,address indexed validator,bytes32 indexed policyHash,bytes32 reasonCode,bytes32 evidenceHash,uint64 expiresAt)",
];
export const createReleaseRegistryV3 = (address: string, runner?: ContractRunner | null) => new Contract(address, releaseRegistryV3Abi, runner);
