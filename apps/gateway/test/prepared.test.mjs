import assert from "node:assert/strict";
import test from "node:test";
import { AbiCoder, id, keccak256 } from "ethers";
import { bytes32, exactReleaseIdentity } from "../../../packages/contracts-sdk/src/v2-identity.mjs";

test("plain Node prepared identity uses the same four-field ABI commitment as Registry V2", () => {
  const input = { toolId: "npm:synthetic-prepared", artifactDigest: `sha256:${"a".repeat(64)}`, manifestDigest: `sha256:${"b".repeat(64)}`, toolSurfaceHash: `0x${"c".repeat(64)}` };
  const expected = keccak256(AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "bytes32", "bytes32"], [id(input.toolId), `0x${"a".repeat(64)}`, `0x${"b".repeat(64)}`, input.toolSurfaceHash]));
  assert.deepEqual(exactReleaseIdentity(input), { toolId: id(input.toolId), releaseId: expected });
  assert.equal(exactReleaseIdentity({ ...input, toolId: id(input.toolId) }).releaseId, expected);
  for (const field of ["toolId", "artifactDigest", "manifestDigest", "toolSurfaceHash"]) assert.notEqual(exactReleaseIdentity({ ...input, [field]: `0x${"d".repeat(64)}` }).releaseId, expected);
  assert.equal(bytes32(input.artifactDigest), `0x${"a".repeat(64)}`);
  assert.throws(() => bytes32("sha256:invalid"), /INVALID_DIGEST/);
});
