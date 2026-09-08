import { AbiCoder, Contract, id, keccak256, type ContractRunner } from "ethers";

export const attestationV2Types = { Attestation: [
  { name: "releaseId", type: "bytes32" }, { name: "artifactDigest", type: "bytes32" },
  { name: "manifestDigest", type: "bytes32" }, { name: "toolSurfaceDigest", type: "bytes32" },
  { name: "policyHash", type: "bytes32" }, { name: "reportRoot", type: "bytes32" },
  { name: "verdict", type: "uint8" }, { name: "validFrom", type: "uint64" },
  { name: "validUntil", type: "uint64" }, { name: "validatorSetVersion", type: "uint32" },
  { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" },
] };
export const attestationV2Domain = (chainId: number | bigint, verifyingContract: string) => ({
  name: "MCPShieldReleaseRegistry", version: "1", chainId, verifyingContract,
});
export function bytes32(value: string) {
  if (/^sha256:[0-9a-f]{64}$/.test(value)) return `0x${value.slice(7)}`;
  if (/^0x[0-9a-f]{64}$/.test(value)) return value;
  throw new Error("INVALID_DIGEST");
}
export function exactReleaseIdentity(input: { toolId: string; artifactDigest: string; manifestDigest: string; toolSurfaceHash: string }) {
  const toolId = /^(?:sha256:|0x)[0-9a-f]{64}$/.test(input.toolId) ? bytes32(input.toolId) : id(input.toolId);
  return { toolId, releaseId: keccak256(AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "bytes32", "bytes32", "bytes32"], [toolId, bytes32(input.artifactDigest), bytes32(input.manifestDigest), bytes32(input.toolSurfaceHash)],
  )) };
}
export const releaseRegistryV2Abi = [
  "function registerRelease(bytes32 toolId,bytes32 artifact,bytes32 manifest,bytes32 surface) returns (bytes32)",
  "function releases(bytes32) view returns (bytes32 toolId,bytes32 artifactDigest,bytes32 manifestDigest,bytes32 toolSurfaceDigest,bool exists)",
  "function getDecision(bytes32 releaseId,bytes32 policyHash) view returns ((bytes32 reportRoot,uint64 validFrom,uint64 validUntil,uint64 quarantineUntil,uint32 validatorSetVersion,uint8 approvals,uint8 rejections,uint8 status))",
  "function submitAttestation((bytes32 releaseId,bytes32 artifactDigest,bytes32 manifestDigest,bytes32 toolSurfaceDigest,bytes32 policyHash,bytes32 reportRoot,uint8 verdict,uint64 validFrom,uint64 validUntil,uint32 validatorSetVersion,uint256 nonce,uint256 deadline) a,bytes signature)",
  "function nonces(address) view returns (uint256)",
  "function validators() view returns (address)",
  "function policies() view returns (address)",
  "function quarantine(bytes32 releaseId,bytes32 policyHash,bytes32 evidenceHash,bytes32 reasonCode,uint64 expiresAt)",
  "function syncExpiry(bytes32 releaseId,bytes32 policyHash)",
  "event ReleaseRegistered(bytes32 indexed releaseId,bytes32 indexed toolId,bytes32 artifactDigest,bytes32 manifestDigest,bytes32 toolSurfaceDigest)",
  "event AttestationAccepted(bytes32 indexed releaseId,address indexed validator,bytes32 indexed policyHash,uint8 verdict,bytes32 reportRoot,uint64 validUntil)",
  "event ReleaseStatusChanged(bytes32 indexed releaseId,bytes32 indexed policyHash,uint8 previousStatus,uint8 newStatus,bytes32 reasonCode,bytes32 evidenceRoot)",
] as const;
export const createReleaseRegistryV2 = (address: string, runner?: ContractRunner) => new Contract(address, releaseRegistryV2Abi, runner);
