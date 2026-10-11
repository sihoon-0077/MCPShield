import assert from "node:assert/strict";
import test from "node:test";
import { createServer } from "node:http";
import { setTimeout as pause } from "node:timers/promises";
import { AbiCoder, Wallet } from "ethers";
import ganache from "ganache";
import { deployV2 } from "../../contracts/scripts/deploy-v2.js";
import { v2ChainReader } from "../../packages/contracts-sdk/src/v2-chain-reader.mjs";

const registryContract = "0x" + "1".repeat(40), validator = "0x" + "2".repeat(40);
const encodedValidator = AbiCoder.defaultAbiCoder().encode(["address"], [validator]);
type RpcCall = { method: string; params: any[]; id: number; jsonrpc: string };
async function localRpc(modify: (call: RpcCall, path: string) => unknown = () => undefined) {
  const calls: { method: string; path: string }[] = [];
  let active = 0;
  const server = createServer(async (request, response) => {
    active++; response.on("close", () => active--);
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    const call: RpcCall = JSON.parse(Buffer.concat(chunks).toString()), path = request.url!;
    calls.push({ method: call.method, path });
    const altered: any = modify(call, path);
    if (altered?.hang) { response.writeHead(200, { "content-type": "application/json" }); response.write("{"); return; }
    if (altered?.outage) { response.writeHead(503).end("PRIVATE_RPC_ERROR"); return; }
    const result = altered?.result ?? ({ eth_chainId: "0x539", eth_getBlockByNumber: {
      number: "0x4", timestamp: "0x" + Math.floor(Date.now() / 1000).toString(16), hash: "0x" + "a".repeat(64),
    }, eth_getCode: "0x6000", eth_call: encodedValidator } as Record<string, unknown>)[call.method];
    response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(altered?.envelope ?? { jsonrpc: "2.0", id: call.id, result }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(server.address() as any).port}`;
  return { url, calls, active: () => active, close: async () => { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); } };
}

test("V2 health is bounded read-only availability, rejects untrusted endpoints without trying a healthy alternative", async () => {
  const cases = [
    { name: "healthy", code: "CHAIN_READY" },
    { name: "wrong-chain", method: "eth_chainId", result: "0x1", code: "CHAIN_ID_MISMATCH" },
    { name: "malformed-chain", method: "eth_chainId", result: "0x0539", code: "CHAIN_TRUST_REJECTED" },
    { name: "stale-head", method: "eth_getBlockByNumber", result: { number: "0x4", hash: "0x" + "a".repeat(64), timestamp: "0x1" }, code: "CHAIN_HEAD_STALE" },
    { name: "future-head", method: "eth_getBlockByNumber", result: { number: "0x4", hash: "0x" + "a".repeat(64), timestamp: "0x" + (Math.floor(Date.now() / 1000) + 120).toString(16) }, code: "CHAIN_HEAD_STALE" },
    { name: "invalid-head", method: "eth_getBlockByNumber", result: { number: "0x4", hash: "0x" + "0".repeat(64), timestamp: "0x1" }, code: "CHAIN_HEAD_INVALID" },
    { name: "missing-code", method: "eth_getCode", result: "0x", code: "CHAIN_REGISTRY_UNAVAILABLE" },
    { name: "odd-code", method: "eth_getCode", result: "0x123", code: "CHAIN_REGISTRY_UNAVAILABLE" },
    { name: "missing-validator", method: "eth_call", result: "0x" + "0".repeat(64), code: "CHAIN_REGISTRY_UNAVAILABLE" },
    { name: "malformed-validator", method: "eth_call", result: "0x123", code: "CHAIN_REGISTRY_UNAVAILABLE" },
    { name: "private-error", method: "eth_chainId", envelope: { jsonrpc: "2.0", id: 1, error: { message: "PRIVATE_RPC_ERROR", code: -1 } }, code: "CHAIN_TRUST_REJECTED" },
  ];
  for (const item of cases) {
    const rpc = await localRpc((call, path) => path === "/first" && call.method === item.method ? item : undefined);
    const reader = v2ChainReader({ rpcUrls: [rpc.url + "/first", rpc.url + "/second"], registryContract, chainId: 1337, confirmations: 1, timeoutMs: 1000 });
    try {
      assert.deepEqual(await reader.health(), { status: item.name === "healthy" ? "UP" : "DOWN", code: item.code }, item.name);
      assert.ok(rpc.calls.length > 0); assert.ok(rpc.calls.every(call => call.path === "/first"), item.name);
      assert.ok(rpc.calls.every(call => ["eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_call"].includes(call.method)));
    } finally { reader.close(); await rpc.close(); }
  }
});

test("V2 health shares a total deadline across transport-only fallback and cancels active requests on close without retries", async () => {
  const rpc = await localRpc((_call, path) => path === "/healthy" ? undefined : path === "/outage" ? { outage: true } : { hang: true });
  const config = { registryContract, chainId: 1337, confirmations: 1, timeoutMs: 250 };
  const recovered = v2ChainReader({ ...config, rpcUrls: [rpc.url + "/slow", rpc.url + "/healthy"] });
  const recovered503 = v2ChainReader({ ...config, rpcUrls: [rpc.url + "/outage", rpc.url + "/healthy"] });
  const unavailable = v2ChainReader({ ...config, rpcUrls: [1, 2, 3].map(n => rpc.url + "/slow" + n) });
  const closed = v2ChainReader({ ...config, timeoutMs: 1500, rpcUrls: [rpc.url + "/closing"] });
  try {
    assert.deepEqual(await recovered.health(), { status: "UP", code: "CHAIN_READY" });
    assert.deepEqual(await recovered503.health(), { status: "UP", code: "CHAIN_READY" });
    const started = performance.now();
    assert.deepEqual(await unavailable.health(), { status: "DOWN", code: "CHAIN_TRANSPORT_UNAVAILABLE" });
    assert.ok(performance.now() - started < 900);
    assert.equal(rpc.calls.filter(call => /^\/slow\d$/.test(call.path)).length, 3);
    const pending = closed.health();
    for (let attempt = 0; attempt < 30 && !rpc.calls.some(call => call.path === "/closing"); attempt++) await pause(5);
    assert.ok(rpc.calls.some(call => call.path === "/closing"));
    closed.close();
    assert.deepEqual(await pending, { status: "DOWN", code: "CHAIN_READER_CLOSED" });
    assert.deepEqual(await closed.health(), { status: "DOWN", code: "CHAIN_READER_CLOSED" });
    const observed = rpc.calls.length;
    await pause(1100); // Detect ethers-style delayed network-startup retry regressions.
    assert.equal(rpc.calls.length, observed); assert.equal(rpc.active(), 0);
  } finally { recovered.close(); recovered503.close(); unavailable.close(); closed.close(); await rpc.close(); }
});

test("negative registry proof wins over simultaneous transport timeout instead of trusting a later endpoint", async () => {
  const rpc = await localRpc((call, path) => path !== "/first" ? undefined :
    call.method === "eth_getCode" ? { result: "0x" } : call.method === "eth_call" ? { hang: true } : undefined);
  const reader = v2ChainReader({ rpcUrls: [rpc.url + "/first", rpc.url + "/second"], registryContract, chainId: 1337, confirmations: 1, timeoutMs: 300 });
  try {
    assert.deepEqual(await reader.health(), { status: "DOWN", code: "CHAIN_REGISTRY_UNAVAILABLE" });
    assert.ok(rpc.calls.every(call => call.path === "/first"));
  } finally { reader.close(); await rpc.close(); }
});

test("V2 health checks a genuinely deployed local registry without any release, attestation or health-triggered transaction", { timeout: 30000 }, async () => {
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 5 } });
  await chain.listen(0, "127.0.0.1");
  const rpc = `http://127.0.0.1:${chain.address().port}`;
  const accounts = Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[];
  let reader: ReturnType<typeof v2ChainReader> | undefined;
  try {
    const deployed = await deployV2(rpc, accounts[0].secretKey, accounts.slice(1, 4).map(account => new Wallet(account.secretKey).address), 1337);
    const before = await chain.provider.request({ method: "eth_blockNumber", params: [] });
    reader = v2ChainReader({ rpcUrls: [rpc], registryContract: deployed.releaseRegistry.address, chainId: 1337, confirmations: 1 });
    assert.deepEqual(await reader.health(), { status: "UP", code: "CHAIN_READY" });
    assert.equal(await chain.provider.request({ method: "eth_blockNumber", params: [] }), before);
  } finally { reader?.close(); await chain.close(); }
});
