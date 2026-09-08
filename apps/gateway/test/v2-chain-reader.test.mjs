import assert from "node:assert/strict";
import test from "node:test";
import { v2ChainReader } from "../../../packages/contracts-sdk/src/v2-chain-reader.mjs";
import { syntheticRpc, h } from "./fixtures/synthetic-rpc.mjs";

test("plain Node shared reader pins exact identity, both decision views, freshness and uncached canonical block references", async () => {
  const rpc = await syntheticRpc(), reader = v2ChainReader({ ...rpc, confirmations: 2 });
  try {
    const accepted = await reader(rpc.identity, rpc);
    assert.equal(accepted.status, "VERIFIED"); assert.equal(accepted.observedBlock, 2); assert.equal(accepted.blockHash, h("2"));
    assert.equal(rpc.counts.get("latest"), 2); assert.equal(rpc.counts.get("0x2"), 2, "Canonical recheck must reach transport, not ethers cache");
    for (rpc.mode of ["identity", "latest-reorg", "confirmed-reorg", "moving-head", "zero-head", "zero-confirmed", "stale-head", "future-head", "expired", "future-validity"]) {
      rpc.counts.clear(); await assert.rejects(reader(rpc.identity, rpc), /STATUS_UNAVAILABLE/);
    }
    rpc.mode = "attestation-drift"; rpc.counts.clear(); assert.equal((await reader(rpc.identity, rpc)).unavailable, true);
    rpc.mode = "revoked"; rpc.counts.clear(); const revoked = await reader(rpc.identity, rpc);
    assert.equal(revoked.status, "REVOKED"); assert.equal(revoked.observedBlock, 3);
    reader.close(); await assert.rejects(reader(rpc.identity, rpc), /STATUS_UNAVAILABLE/);
  } finally { reader.close(); await rpc.close(); }
});
