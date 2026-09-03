import { Contract, id, type ContractRunner } from "ethers";
import type { ReleaseStatus } from "../../protocol/api/types.js";

export const releaseRegistryAbi = [
  "function QUORUM() view returns (uint8)",
  "function isValidator(address) view returns (bool)",
  "function hasVoted(bytes32,address) view returns (bool)",
  "function releaseKey(string) pure returns (bytes32)",
  "function registerRelease(string releaseId,bytes32 artifactDigest,bytes32 toolSurfaceHash) returns (bytes32)",
  "function submitVote(bytes32 key,uint8 decision,bytes32 evidenceHash)",
  "function getRelease(bytes32 key) view returns ((string releaseId,bytes32 artifactDigest,bytes32 toolSurfaceHash,uint8 status,uint8 passVotes,uint8 failVotes,bool exists))",
  "event ReleaseRegistered(bytes32 indexed releaseKey,string releaseId,bytes32 artifactDigest,bytes32 toolSurfaceHash)",
  "event VoteSubmitted(bytes32 indexed releaseKey,address indexed validator,uint8 decision,bytes32 indexed evidenceHash)",
  "event StatusChanged(bytes32 indexed releaseKey,uint8 previousStatus,uint8 newStatus)",
] as const;

export const chainStatuses: readonly ReleaseStatus[] = [
  "UNVERIFIED",
  "VERIFIED",
  "QUARANTINED",
  "REVOKED",
];

export const chainDecisions = { PASS: 0, FAIL: 1, ABSTAIN: 2 } as const;

export function releaseKey(releaseId: string) {
  return id(releaseId);
}

export function artifactDigestToBytes32(digest: string) {
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) {
    throw new Error("Invalid artifact digest");
  }
  return `0x${digest.slice("sha256:".length)}`;
}

export function createReleaseRegistry(address: string, runner?: ContractRunner) {
  return new Contract(address, releaseRegistryAbi, runner);
}

export function statusFromChain(value: bigint | number): ReleaseStatus {
  const status = chainStatuses[Number(value)];
  if (!status) throw new Error(`Unknown chain status: ${value}`);
  return status;
}
