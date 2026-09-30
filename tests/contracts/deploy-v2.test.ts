import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";

test("deployment helper and preflight naturally exit after early RPC failures without private diagnostics", async () => {
  let mode = "unavailable";
  const server = createServer(async (request, response) => {
    let text = ""; for await (const chunk of request) text += chunk;
    const body = JSON.parse(text), calls = Array.isArray(body) ? body : [body];
    if (mode === "unavailable" || calls.some(call => call.method === "eth_getBalance")) {
      response.writeHead(503, { connection: "close" }).end("SYNTHETIC_PRIVATE_RPC_RESPONSE"); return;
    }
    const replies = calls.map(call => ({ jsonrpc: "2.0", id: call.id, result: "0x539" }));
    response.writeHead(200, { "content-type": "application/json", connection: "close" }).end(JSON.stringify(Array.isArray(body) ? replies : replies[0]));
  });
  try {
    await new Promise<void>(done => server.listen(0, "127.0.0.1", done));
    const rpc = `http://127.0.0.1:${(server.address() as any).port}/private-rpc?token=SYNTHETIC_RPC_TOKEN`, key = "1".repeat(64);
    const validators = ["a", "b", "c"].map(char => `0x${char.repeat(40)}`), module = new URL("../../contracts/scripts/deploy-v2.ts", import.meta.url);
    const scenarios = [
      { cli: false, mode: "unavailable", chainId: 1337, validators, expected: "SERVICE_TRANSPORT_UNAVAILABLE" },
      { cli: true, mode: "unavailable", chainId: 1337, validators, expected: "SERVICE_TRANSPORT_UNAVAILABLE" },
      { cli: false, mode: "available", chainId: 1338, validators, expected: "CHAIN_ID_MISMATCH" },
      { cli: false, mode: "available", chainId: 1337, validators: [validators[0], validators[0], validators[0]], expected: "THREE_UNIQUE_VALIDATORS_REQUIRED" },
      { cli: true, mode: "available", chainId: 1337, validators, expected: "SERVICE_TRANSPORT_UNAVAILABLE" },
    ];
    for (const scenario of scenarios) {
      mode = scenario.mode;
      const args = scenario.cli ? ["--import", "tsx", fileURLToPath(module)] : ["--import", "tsx", "--input-type=module", "--eval",
        `import { deployV2 } from ${JSON.stringify(module.href)}; try { await deployV2(process.env.CONTROL_V2_RPC_URLS,process.env.DEPLOYER_PRIVATE_KEY,process.env.VALIDATOR_ADDRESSES.split(','),Number(process.env.CONTROL_V2_CHAIN_ID)); } catch(error) { console.error(error.message); process.exitCode=1; }`];
      const result = await new Promise<{ error: any; stdout: string; stderr: string }>(done => execFile(process.execPath, args,
        { timeout: 7000, maxBuffer: 64 * 1024, windowsHide: true, env: { ...process.env, CONTROL_V2_RPC_URLS: rpc,
          DEPLOYER_PRIVATE_KEY: key, VALIDATOR_ADDRESSES: scenario.validators.join(","), CONTROL_V2_CHAIN_ID: String(scenario.chainId) } },
        (error, stdout, stderr) => done({ error, stdout, stderr })));
      assert.ok(result.error, "preflight must fail, never approve missing RPC");
      assert.notEqual(result.error.killed, true, `${scenario.cli ? "CLI" : "helper"} ${scenario.expected} leaked handles after rejection`);
      assert.equal(result.error.signal, null); assert.equal(result.error.code, 1);
      assert.match(result.stderr, new RegExp(scenario.expected));
      for (const privateText of [rpc, "private-rpc", "SYNTHETIC_RPC_TOKEN", "SYNTHETIC_PRIVATE_RPC_RESPONSE", key]) assert.ok(!`${result.stdout}${result.stderr}`.includes(privateText));
    }
  } finally { server.closeAllConnections(); await new Promise<void>(done => server.close(() => done())); }
});

test("fullcycle early setup rejection leaves no handles in its own process", async () => {
  const environment = { ...process.env }; delete environment.NODE_TEST_CONTEXT;
  const result = await new Promise<{ error: any; stdout: string; stderr: string }>(done => execFile(process.execPath,
    ["--import", "tsx", "--test", "--test-isolation=none", "--test-name-pattern=V2 early setup failure", fileURLToPath(new URL("../api/v2-fullcycle.test.ts", import.meta.url))],
    { timeout: 10000, maxBuffer: 64 * 1024, windowsHide: true, env: environment }, (error, stdout, stderr) => done({ error, stdout, stderr })));
  assert.equal(result.error, null, `child must exit naturally; a passing subtest alone does not prove cleanup: ${result.error?.message}`);
  assert.match(result.stdout, /pass 1/); assert.match(result.stdout, /fail 0/);
});
