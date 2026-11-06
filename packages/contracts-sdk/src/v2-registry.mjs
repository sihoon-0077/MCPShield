import { Contract } from "ethers";

export const releaseRegistryV2Abi = [
  "function registerRelease(bytes32 toolId,bytes32 artifact,bytes32 manifest,bytes32 surface) returns (bytes32)",
  "function releases(bytes32) view returns (bytes32 toolId,bytes32 artifactDigest,bytes32 manifestDigest,bytes32 toolSurfaceDigest,bool exists)",
  "function getDecision(bytes32 releaseId,bytes32 policyHash) view returns ((bytes32 reportRoot,uint64 validFrom,uint64 validUntil,uint64 quarantineUntil,uint32 validatorSetVersion,uint8 approvals,uint8 rejections,uint8 status))",
  "function submitAttestation((bytes32 releaseId,bytes32 artifactDigest,bytes32 manifestDigest,bytes32 toolSurfaceDigest,bytes32 policyHash,bytes32 reportRoot,uint8 verdict,uint64 validFrom,uint64 validUntil,uint32 validatorSetVersion,uint256 nonce,uint256 deadline) a,bytes signature)",
  "function nonces(address) view returns (uint256)",
  "function usedDigest(bytes32) view returns (bool)",
  "function validators() view returns (address)",
  "function policies() view returns (address)",
  "function quarantine(bytes32 releaseId,bytes32 policyHash,bytes32 evidenceHash,bytes32 reasonCode,uint64 expiresAt)",
  "function quarantineBySignature((bytes32 releaseId,bytes32 policyHash,bytes32 evidenceHash,bytes32 reasonCode,uint64 expiresAt,uint32 validatorSetVersion,uint256 nonce,uint256 deadline) q,bytes signature)",
  "function syncExpiry(bytes32 releaseId,bytes32 policyHash)",
  "event ReleaseRegistered(bytes32 indexed releaseId,bytes32 indexed toolId,bytes32 artifactDigest,bytes32 manifestDigest,bytes32 toolSurfaceDigest)",
  "event AttestationAccepted(bytes32 indexed releaseId,address indexed validator,bytes32 indexed policyHash,uint8 verdict,bytes32 reportRoot,uint64 validUntil)",
  "event ReleaseStatusChanged(bytes32 indexed releaseId,bytes32 indexed policyHash,uint8 previousStatus,uint8 newStatus,bytes32 reasonCode,bytes32 evidenceRoot)",
];
export const createReleaseRegistryV2 = (address, runner) => new Contract(address, releaseRegistryV2Abi, runner);
