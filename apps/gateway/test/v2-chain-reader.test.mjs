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
    assert.equal(rpc.counts.get("0x3"), 1, "ADR-009: the head block of the view is re-read by number");
    for (rpc.mode of ["identity", "latest-reorg", "head-reorg", "confirmed-reorg", "runaway-head", "zero-head", "zero-confirmed", "stale-head", "future-head", "expired", "future-validity"]) {
      rpc.counts.clear(); await assert.rejects(reader(rpc.identity, rpc), /STATUS_UNAVAILABLE/);
    }
    rpc.mode = "attestation-drift"; rpc.counts.clear(); assert.equal((await reader(rpc.identity, rpc)).unavailable, true);
    rpc.mode = "revoked"; rpc.counts.clear(); const revoked = await reader(rpc.identity, rpc);
    assert.equal(revoked.status, "REVOKED"); assert.equal(revoked.observedBlock, 3);
    reader.close(); await assert.rejects(reader(rpc.identity, rpc), /STATUS_UNAVAILABLE/);
  } finally { reader.close(); await rpc.close(); }
});

test("ADR-009: a grown head keeps a canonical view, a newer denial or reorg never yields the first allow", async () => {
  const rpc = await syntheticRpc("fresh-view"), reader = v2ChainReader({ ...rpc, confirmations: 2 });
  try {
    // Base produces a block every 2 s; a head that grew by up to MAX_HEAD_ADVANCE blocks is not a reason to deny.
    for (const mode of ["moving-head", "continuous-head", "lagging-backend"]) {
      rpc.mode = mode; rpc.counts.clear(); rpc.requests.length = 0;
      const decision = await reader(rpc.identity, rpc);
      assert.equal(decision.status, "VERIFIED", mode);
      assert.equal(decision.observedBlock, 2); assert.equal(decision.blockHash, h("2"));
      assert.equal(rpc.counts.get("latest"), mode === "lagging-backend" ? 4 : 2, `${mode}: one view, plus one fresh view only for a lagging backend`);
    }
    // A revocation in a newer block than the view: the newest-state probe forces one fresh view that returns the denial.
    rpc.mode = "advance-revoked"; rpc.counts.clear(); rpc.requests.length = 0;
    const revoked = await reader(rpc.identity, rpc);
    assert.deepEqual([revoked.status, revoked.headBlock, revoked.observedBlock, revoked.blockHash], ["REVOKED", 4, 4, h("4")]);
    assert.ok(rpc.requests.some(request => request.method === "eth_call" && request.params[1] === "latest"), "ALLOW needs the provider's newest state too");
    // A denial at the view's own head is returned as that denial, not as an outage.
    rpc.mode = "advance-negative"; rpc.counts.clear();
    assert.equal((await reader(rpc.identity, rpc)).status, "REVOKED");
    // A lagging backend that has not seen the view's head yet cannot turn a denial into an outage.
    rpc.mode = "lagging-revoked"; rpc.counts.clear();
    assert.equal((await reader(rpc.identity, rpc)).status, "REVOKED");
    for (const mode of ["latest-reorg", "head-reorg", "confirmed-reorg", "runaway-head"]) {
      rpc.mode = mode; rpc.counts.clear();
      await assert.rejects(reader(rpc.identity, rpc), /STATUS_UNAVAILABLE/, mode);
    }
    const alternatives = v2ChainReader({ ...rpc, rpcUrls: [1, 2, 3].map(number => `${rpc.rpcUrls[0]}/${number}`), confirmations: 2 });
    try {
      for (const mode of ["latest-reorg", "head-reorg", "confirmed-reorg", "runaway-head"]) {
        rpc.mode = mode; rpc.counts.clear(); rpc.requests.length = 0;
        await assert.rejects(alternatives(rpc.identity, rpc), /STATUS_UNAVAILABLE/);
        assert.ok(rpc.requests.every(request => request.path === "/1"), "An inconsistent view or exhausted fresh-view retry cannot sample another provider for ALLOW");
      }
    } finally { alternatives.close(); }
  } finally { reader.close(); await rpc.close(); }
});

test("ADR-009: a newer denial seen once is never forgotten by the retry or by failover to another RPC", async () => {
  const rpc = await syntheticRpc("sticky-denial");
  try {
    // The retry lands on a lagging backend whose whole view says VERIFIED; the earlier REVOKED still wins.
    rpc.mode = "lb-negative-latest";
    const reader = v2ChainReader({ ...rpc, confirmations: 2 });
    try { await assert.rejects(reader(rpc.identity, rpc), /STATUS_UNAVAILABLE/); } finally { reader.close(); }
    // URL1 shows REVOKED at latest, then stalls; failing over to an untouched URL2 must not produce ALLOW.
    rpc.mode = "valid"; rpc.latestDecisionCalls = 0; rpc.requests.length = 0; rpc.routeModes["/1"] = "neg-then-stall";
    const failover = v2ChainReader({ ...rpc, rpcUrls: [`${rpc.rpcUrls[0]}/1`, `${rpc.rpcUrls[0]}/2`], confirmations: 2, timeoutMs: 3000 });
    try { await assert.rejects(failover(rpc.identity, rpc), /STATUS_UNAVAILABLE/); } finally { failover.close(); }
  } finally { await rpc.close(); }
});

test("fresh-view retry keeps the original total budget and never starts a third view", async () => {
  const rpc = await syntheticRpc("fresh-view-budget"), reader = v2ChainReader({ ...rpc, confirmations: 2, timeoutMs: 300 });
  try {
    rpc.mode = "runaway-budget";
    const started = performance.now();
    await assert.rejects(reader(rpc.identity, rpc), /STATUS_UNAVAILABLE/);
    assert.equal(rpc.counts.get("latest"), 3, "Second view starts, stalls, and is aborted without any third view");
    assert.ok(performance.now() - started < 900, "Retry shares rather than restarts the total deadline");
  } finally { reader.close(); await rpc.close(); }
});
