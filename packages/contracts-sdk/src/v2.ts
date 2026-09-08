export { releaseRegistryV2Abi, createReleaseRegistryV2 } from "./v2-registry.mjs";
export { bytes32, exactReleaseIdentity } from "./v2-identity.mjs";

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
export const quarantineV2Types = { Quarantine: [
  { name: "releaseId", type: "bytes32" }, { name: "policyHash", type: "bytes32" },
  { name: "evidenceHash", type: "bytes32" }, { name: "reasonCode", type: "bytes32" },
  { name: "expiresAt", type: "uint64" }, { name: "validatorSetVersion", type: "uint32" },
  { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" },
] };
