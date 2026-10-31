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

export { releaseRegistryV3Abi, createReleaseRegistryV3 } from "./v3-registry.mjs";
export { VERDICTS, QUARANTINE_REASONS, EVIDENCE_SCHEMA, MAX_EVIDENCE_BYTES, verdictFromFindings, verdictFromReport, quarantineReason,
  evidenceDocument, checkedVoteEvidence, type V3Verdict, type V3Release } from "./v3-evidence.mjs";
