import { AbiCoder, id, keccak256 } from "ethers";

export function bytes32(value) {
  if (/^sha256:[0-9a-f]{64}$/.test(value)) return `0x${value.slice(7)}`;
  if (/^0x[0-9a-f]{64}$/.test(value)) return value;
  throw new Error("INVALID_DIGEST");
}

export function exactReleaseIdentity(input) {
  const toolId = /^(?:sha256:|0x)[0-9a-f]{64}$/.test(input.toolId) ? bytes32(input.toolId) : id(input.toolId);
  return { toolId, releaseId: keccak256(AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "bytes32", "bytes32", "bytes32"], [toolId, bytes32(input.artifactDigest), bytes32(input.manifestDigest), bytes32(input.toolSurfaceHash)],
  )) };
}
