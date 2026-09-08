import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import test from "node:test";
import { setTimeout } from "node:timers/promises";
import { v2ChainReader, V2ChainUnavailableError } from "../../../packages/contracts-sdk/src/v2-chain-reader.mjs";
import { boundedServiceRequest, TransportUnavailableError } from "../../../packages/contracts-sdk/src/transport.mjs";
import { syntheticRpc } from "./fixtures/synthetic-rpc.mjs";

const kind = expected => error => {
  assert.ok(error instanceof V2ChainUnavailableError); assert.equal(error.failureKind, expected);
  assert.equal(error.message, "STATUS_UNAVAILABLE"); assert.doesNotMatch(JSON.stringify(error), /https?:|synthetic-private/); return true;
};

test("fair-share provider deadline advances from stalled first RPC to fully verified healthy RPC", async () => {
  const rpc = await syntheticRpc("fairshare"), base = rpc.rpcUrls[0]; rpc.routeModes["/slow"] = "timeout";
  const reader = v2ChainReader({ ...rpc, rpcUrls: [`${base}/slow`, `${base}/healthy`], confirmations: 2, timeoutMs: 1000 });
  const started = performance.now();
  try {
    const result = await reader(rpc.identity, rpc); assert.equal(result.status, "VERIFIED");
    assert.ok(rpc.requests.some(request => request.path === "/slow")); assert.ok(rpc.requests.some(request => request.path === "/healthy"));
    assert.ok(performance.now() - started < 1300);
  } finally { reader.close(); await rpc.close(); }
});

test("all three actual transport failures are typed only after every endpoint was attempted inside one deadline", async () => {
  const rpc = await syntheticRpc("all-outage"), base = rpc.rpcUrls[0];
  const reader = v2ChainReader({ ...rpc, rpcUrls: [1, 2, 3].map(n => `${base}/${n}`), confirmations: 2, timeoutMs: 600 });
  try {
    for (const mode of ["http503", "timeout"]) {
      rpc.mode = mode; rpc.requests.length = 0; const started = performance.now();
      await assert.rejects(reader(rpc.identity, rpc), kind("TRANSPORT_UNAVAILABLE"));
      assert.deepEqual([...new Set(rpc.requests.map(request => request.path))], ["/1", "/2", "/3"]);
      assert.ok(performance.now() - started < 1000);
    }
  } finally { reader.close(); await rpc.close(); }
});

test("invalid first RPC can never be bypassed by a healthy second endpoint or relabeled as transport outage", async () => {
  const rpc = await syntheticRpc("trust-reject"), base = rpc.rpcUrls[0];
  const reader = v2ChainReader({ ...rpc, rpcUrls: [`${base}/invalid`, `${base}/healthy`], confirmations: 2, timeoutMs: 600 });
  try {
    for (const mode of ["http403", "redirect", "oversized", "bad-json", "rpc-error", "wrong-id", "identity", "expired", "stale-head", "future-head", "latest-reorg", "confirmed-reorg", "mixed-failure", "partial-negative",
      "revoked-version-timeout", "identity-timeout", "expired-timeout", "after-head-reorg-timeout", "after-confirmed-reorg-timeout", "stale-head-timeout", "zero-validator-timeout"]) {
      rpc.routeModes["/invalid"] = mode; rpc.requests.length = 0; rpc.counts.clear();
      await assert.rejects(reader(rpc.identity, rpc), kind("TRUST_REJECTED"));
      assert.ok(rpc.requests.every(request => request.path === "/invalid"), mode);
    }
    rpc.routeModes["/invalid"] = "stale-head-revoked"; rpc.counts.clear(); rpc.requests.length = 0;
    assert.equal((await reader(rpc.identity, rpc)).status, "REVOKED", "Stale negative history remains a normal denial, never ALLOW evidence");
    assert.ok(rpc.requests.every(request => request.path === "/invalid"));
  } finally { reader.close(); await rpc.close(); }
});

test("operator close and external cancellation are trust rejection, not an emergency outage credential", async () => {
  const rpc = await syntheticRpc("closed-reader"), base = rpc.rpcUrls[0]; rpc.mode = "timeout";
  const reader = v2ChainReader({ ...rpc, rpcUrls: [`${base}/one`, `${base}/two`], confirmations: 2, timeoutMs: 600 });
  try {
    const result = reader(rpc.identity, rpc); const rejected = assert.rejects(result, kind("TRUST_REJECTED"));
    while (!rpc.requests.length) await setTimeout(1);
    reader.close(); await rejected;
    assert.ok(rpc.requests.every(request => request.path === "/one"));
    const abort = new AbortController();
    const request = boundedServiceRequest(base, { method: "POST", body: JSON.stringify({ method: "eth_chainId" }), signal: abort.signal }, { timeoutMs: 500 });
    const cancelled = assert.rejects(request, error => !(error instanceof TransportUnavailableError) && error.message === "SERVICE_REQUEST_CANCELLED");
    abort.abort(new Error("synthetic-policy-cancel")); await cancelled;
  } finally { reader.close(); await rpc.close(); }
});

test("a delayed timer cannot return ALLOW after either total or provider monotonic deadline", async () => {
  const rpc = await syntheticRpc("final-time-fence"), base = rpc.rpcUrls[0];
  try {
    for (const [urls, advance] of [[[base], 2000], [[`${base}/first`, `${base}/unreached`], 600]]) {
      rpc.requests.length = 0; rpc.counts.clear();
      const code = `import {v2ChainReader,V2ChainUnavailableError} from ${JSON.stringify(new URL("../../../packages/contracts-sdk/src/v2-chain-reader.mjs", import.meta.url).href)};
        const input=JSON.parse(process.argv[1]), real=performance.now.bind(performance);let checks=0;
        Object.defineProperty(performance,'now',{value:()=>{const caller=new Error().stack.split('\\n')[2]??'';
          return real()+(caller.includes('v2-chain-reader.mjs')&&++checks>=4?input.advance:0);}});
        const reader=v2ChainReader(input.config);try{await reader(input.identity,input.policy);console.log('UNEXPECTED_ALLOW');}
        catch(e){console.log(e instanceof V2ChainUnavailableError?e.failureKind:'UNEXPECTED_ERROR');}finally{reader.close();}`;
      const child = spawn(process.execPath, ["--input-type=module", "-e", code, JSON.stringify({ advance,
        config: { rpcUrls: urls, registryContract: rpc.registryContract, chainId: rpc.chainId, confirmations: 2, timeoutMs: 1000 }, identity: rpc.identity, policy: { policyHash: rpc.policyHash } })], { windowsHide: true, stdio: ["ignore", "pipe", "ignore"] });
      let stdout = ""; child.stdout.on("data", chunk => { stdout += chunk; });
      const timer = globalThis.setTimeout(() => child.kill(), 5000);
      try { await new Promise((resolve, reject) => { child.once("error", reject); child.once("close", resolve); }); }
      finally { clearTimeout(timer); }
      assert.equal(stdout.trim(), "TRUST_REJECTED"); assert.ok(rpc.requests.every(request => request.path !== "/unreached"));
    }
  } finally { await rpc.close(); }
});
