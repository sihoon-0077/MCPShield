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
    for (rpc.mode of ["identity", "latest-reorg", "confirmed-reorg", "continuous-head", "zero-head", "zero-confirmed", "stale-head", "future-head", "expired", "future-validity"]) {
      rpc.counts.clear(); await assert.rejects(reader(rpc.identity, rpc), /STATUS_UNAVAILABLE/);
    }
    rpc.mode = "attestation-drift"; rpc.counts.clear(); assert.equal((await reader(rpc.identity, rpc)).unavailable, true);
    rpc.mode = "revoked"; rpc.counts.clear(); const revoked = await reader(rpc.identity, rpc);
    assert.equal(revoked.status, "REVOKED"); assert.equal(revoked.observedBlock, 3);
    reader.close(); await assert.rejects(reader(rpc.identity, rpc), /STATUS_UNAVAILABLE/);
  } finally { reader.close(); await rpc.close(); }
});

test("one benign head extension re-reads the entire fresh view and never returns the first allow", async () => {
  const rpc = await syntheticRpc("fresh-view"), reader = v2ChainReader({ ...rpc, confirmations: 2 });
  try {
    for (const mode of ["moving-head", "advance-revoked"]) {
      rpc.mode = mode; rpc.counts.clear(); rpc.requests.length = 0;
      const decision = await reader(rpc.identity, rpc);
      assert.equal(decision.status, mode === "advance-revoked" ? "REVOKED" : "VERIFIED");
      assert.equal(decision.headBlock, 4); assert.equal(decision.observedBlock, mode === "advance-revoked" ? 4 : 3);
      assert.equal(decision.blockHash, h(mode === "advance-revoked" ? "4" : "3"));
      assert.equal(rpc.counts.get("latest"), 4, "Both full views require uncached post-query checks");
      const contractTags = rpc.requests.filter(request => request.method === "eth_call").map(request => request.params[1]);
      assert.ok(contractTags.includes("0x4") && contractTags.includes("0x3"));
    }
    for (const mode of ["advance-identity", "advance-expired", "advance-negative", "latest-reorg", "confirmed-reorg", "continuous-head"]) {
      rpc.mode = mode; rpc.counts.clear();
      await assert.rejects(reader(rpc.identity, rpc), /STATUS_UNAVAILABLE/);
      assert.equal(rpc.counts.get("latest"), ["advance-negative", "latest-reorg", "confirmed-reorg"].includes(mode) ? 2 : mode === "continuous-head" ? 4 : 3,
        "Only one benign positive-view retry is permitted");
    }
    rpc.mode = "advance-drift"; rpc.counts.clear();
    assert.equal((await reader(rpc.identity, rpc)).unavailable, true, "Second-view attestation mismatch cannot reuse the first ALLOW");
    const alternatives = v2ChainReader({ ...rpc, rpcUrls: [1, 2, 3].map(number => `${rpc.rpcUrls[0]}/${number}`), confirmations: 2 });
    try {
      for (const mode of ["latest-reorg", "confirmed-reorg", "advance-negative", "continuous-head"]) {
        rpc.mode = mode; rpc.counts.clear(); rpc.requests.length = 0;
        await assert.rejects(alternatives(rpc.identity, rpc), /STATUS_UNAVAILABLE/);
        assert.ok(rpc.requests.every(request => request.path === "/1"), "An inconsistent view or exhausted fresh-view retry cannot sample another provider for ALLOW");
      }
    } finally { alternatives.close(); }
  } finally { reader.close(); await rpc.close(); }
});

test("fresh-view retry keeps the original total budget and never starts a third view", async () => {
  const rpc = await syntheticRpc("fresh-view-budget"), reader = v2ChainReader({ ...rpc, confirmations: 2, timeoutMs: 300 });
  try {
    rpc.mode = "advance-budget";
    const started = performance.now();
    await assert.rejects(reader(rpc.identity, rpc), /STATUS_UNAVAILABLE/);
    assert.equal(rpc.counts.get("latest"), 3, "Second view starts, stalls, and is aborted without any third view");
    assert.ok(performance.now() - started < 900, "Retry shares rather than restarts the total deadline");
  } finally { reader.close(); await rpc.close(); }
});
