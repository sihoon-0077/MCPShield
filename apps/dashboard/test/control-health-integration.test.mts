import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { setTimeout as pause } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { NextRequest } from "next/server";
import ganache from "ganache";
import { Wallet } from "ethers";
import { GET, POST } from "../app/api/control/[...path]/route";
import { parseControlHealth } from "../lib/control-health";
import { buildApp } from "../../api/src/app.js";
import { ControlStore } from "../../api/src/control-store.js";
import { startScannerHeartbeat } from "../../api/src/worker-health.js";
import { deployV2 } from "../../../contracts/scripts/deploy-v2.js";
import { v2ChainReader } from "../../../packages/contracts-sdk/src/v2-chain-reader.mjs";
import { checkControlReadiness } from "../../../scripts/ops/check-control-health.js";

test("real API → authenticated BFF → monitor retains limited scanner status and reports actual local RPC loss", { timeout: 40000 }, async () => {
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true, totalAccounts: 5 } });
  await chain.listen(0, "127.0.0.1");
  let chainClosed = false, app: Awaited<ReturnType<typeof buildApp>> | undefined;
  let heartbeat: ReturnType<typeof startScannerHeartbeat> | undefined;
  let reader: ReturnType<typeof v2ChainReader> | undefined;
  const names = ["MCPSHIELD_API_URL", "MCPSHIELD_PUBLIC_ORIGIN"], previous = names.map(name => process.env[name]);
  try {
    const rpc = `http://127.0.0.1:${chain.address().port}`;
    const accounts = Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[];
    const deployed = await deployV2(rpc, accounts[0].secretKey, accounts.slice(1, 4).map(account => new Wallet(account.secretKey).address), 1337);
    reader = v2ChainReader({ rpcUrls: [rpc], registryContract: deployed.releaseRegistry.address, chainId: 1337, confirmations: 1, timeoutMs: 500 });
    const store = await ControlStore.open();
    const token = "synthetic-health-integration-reader", tenantId = "health-integration";
    const options = { store, credentials: [{ token, tenantId, role: "reader" as const },
      { token: "synthetic-health-integration-operator", tenantId, role: "operator" as const },
      { token: "synthetic-health-integration-foreign", tenantId: "other", role: "reader" as const }],
      artifactPath: "unused", evidencePath: "unused", evidenceKey: "1".repeat(64), chainDecision: reader };
    app = await buildApp({ adminApiToken: "synthetic-legacy-admin", scannerApiToken: "synthetic-legacy-scanner", controlPlane: options });
    await app.listen({ host: "127.0.0.1", port: 0 });
    const api = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
    process.env.MCPSHIELD_API_URL = api; process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
    // Real heartbeat writer and SQL store, intentionally STATIC_ONLY. No Docker or external AI claim.
    heartbeat = startScannerHeartbeat(store, options, "SCAN"); await heartbeat.pulse();
    const login = await POST(new NextRequest("https://console.test/api/control/session", { method: "POST", headers: {
      origin: "https://console.test", "content-type": "application/json" }, body: JSON.stringify({ token }) }), { params: Promise.resolve({ path: ["session"] }) });
    assert.equal(login.status, 200); assert.match(login.headers.get("set-cookie")!, /HttpOnly/i);
    const cookie = login.headers.get("set-cookie")!.split(";")[0];
    const read = (currentCookie = cookie) => GET(new NextRequest("https://console.test/api/control/health", { headers: { cookie: currentCookie } }), { params: Promise.resolve({ path: ["health"] }) });
    const response = await read(), body = parseControlHealth(await response.json(), response.status);
    assert.equal(response.status, 503); assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(body.components.database.status, "UP"); assert.equal(body.components.chain.status, "UP");
    assert.equal(body.components.scanner.status, "LIMITED"); assert.equal(body.status, "DEGRADED");
    assert.doesNotMatch(JSON.stringify(body), /synthetic|127\.0\.0\.1|health-integration|secretKey/);
    const url = `${api}/v1/health`;
    const monitor = await checkControlReadiness({ url, token });
    assert.equal(monitor.status, "DEGRADED"); assert.equal(monitor.components.chain, "UP"); assert.equal(monitor.components.scanner, "LIMITED");
    // Exercise the actual one-shot command and its nonzero gate, without exposing credentials in argv.
    const command = fileURLToPath(new URL("../../../scripts/ops/check-control-health.ts", import.meta.url));
    await assert.rejects(promisify(execFile)(process.execPath, ["--import", "tsx", command], {
      env: { ...process.env, MCPSHIELD_HEALTH_URL: url, MCPSHIELD_HEALTH_TOKEN: token }, timeout: 10000, maxBuffer: 16384, windowsHide: true,
    }), (error: any) => { assert.equal(error.code, 1); assert.equal(JSON.parse(error.stdout).status, "DEGRADED"); assert.doesNotMatch(error.stdout + error.stderr, /synthetic-health|Bearer/); return true; });
    const foreign = await read("mcpshield_control=synthetic-health-integration-foreign");
    assert.equal((await foreign.json()).components.scanner.code, "SCANNER_HEARTBEAT_MISSING");
    const unauthorized = await read("mcpshield_control=synthetic-rejected-health-token");
    assert.equal(unauthorized.status, 401); assert.match(unauthorized.headers.get("set-cookie")!, /Max-Age=0/);
    await heartbeat.stop(); await chain.close(); chainClosed = true;
    // Expire the documented 2-second observation cache; this is not a live browser test.
    await pause(2100);
    const failure = await read(), failed = parseControlHealth(await failure.json(), failure.status);
    assert.equal(failure.status, 503); assert.equal(failed.components.database.status, "UP");
    assert.equal(failed.components.chain.status, "DOWN"); assert.equal(failed.components.scanner.code, "SCANNER_STOPPED");
    const after = await checkControlReadiness({ url, token }); assert.equal(after.components.chain, "DOWN"); assert.equal(after.status, "DEGRADED");
    assert.equal((await fetch(`${api}/health`)).status, 200, "Legacy liveness remains separate from dependency readiness");
  } finally {
    for (const [index, name] of names.entries()) previous[index] === undefined ? delete process.env[name] : process.env[name] = previous[index];
    await heartbeat?.stop(); await app?.close(); reader?.close(); if (!chainClosed) await chain.close();
  }
});
