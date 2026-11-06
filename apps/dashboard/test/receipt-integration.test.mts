import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as pause } from "node:timers/promises";
import test from "node:test";
import { NextRequest } from "next/server";
import ganache from "ganache";
import { Wallet, id } from "ethers";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { GET, POST } from "../app/api/control/[...path]/route";
import { ReceiptRecordsView, ReceiptStatus } from "../components/receipt-console";
import { deployReceipts } from "../../../contracts/scripts/deploy-receipts.js";
import { buildApp } from "../../api/src/app.js";
import { ControlStore } from "../../api/src/control-store.js";
import { ReceiptRelayer } from "../../api/src/receipt-relayer.js";
import { runChainActionOnce } from "../../api/src/chain-outbox.js";
import { anchorLocalReceipts } from "../../validator/src/receipt-writer.js";
// @ts-expect-error Shared Gateway private ledger is ESM JavaScript.
import { openReceiptLedger } from "../../gateway/src/receipts.mjs";

test("receipt BFF with real API/chain: admin registration, CLI anchoring, finality, reorg, evidence privacy and RPC outage", { timeout: 60_000 }, async () => {
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true } });
  await chain.listen(0, "127.0.0.1");
  const rpc = `http://127.0.0.1:${chain.address().port}`, accounts = Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[];
  const writer = new Wallet(accounts[1].secretKey);
  const deployed = await deployReceipts(rpc, accounts[0].secretKey, 1337);
  const relayer = new ReceiptRelayer(rpc, deployed.registryAddress, 1337, accounts[0].secretKey, 2);
  const directory = await mkdtemp(join(tmpdir(), "mcpshield-console-receipts-"));
  const store = await ControlStore.open(join(directory, "control.sqlite")), filename = join(directory, "gateway.sqlite"), ledger = openReceiptLedger(filename);
  const credentials = ["admin", "operator", "reader"].map((role) => ({ tenantId: "receipt-console", token: `synthetic-receipt-${role}-token`, role: role as "admin" | "operator" | "reader" }));
  credentials.push({ tenantId: "foreign", token: "synthetic-foreign-admin-token", role: "admin" });
  const app = await buildApp({ adminApiToken: "synthetic-unused-admin", scannerApiToken: "synthetic-unused-scanner", controlPlane: { store, credentials,
    artifactPath: join(directory, "artifacts"), evidencePath: join(directory, "evidence"), evidenceKey: "e".repeat(64), receiptRelayer: relayer } });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const apiUrl = `http://127.0.0.1:${(app.server.address() as { port: number }).port}`;
  const previous = process.env.MCPSHIELD_API_URL, previousOrigin = process.env.MCPSHIELD_PUBLIC_ORIGIN;
  process.env.MCPSHIELD_API_URL = apiUrl; process.env.MCPSHIELD_PUBLIC_ORIGIN = "https://console.test";
  let closed = false;
  const request = (path: string, cookie = "", body?: unknown, key = "synthetic-ledger-attempt", origin = "https://console.test") => {
    const req = new NextRequest(`https://console.test/api/control/${path}`, { method: body === undefined ? "GET" : "POST", headers: { cookie, origin, "content-type": "application/json", "idempotency-key": key }, body: body === undefined ? undefined : JSON.stringify(body) });
    return (body === undefined ? GET : POST)(req, { params: Promise.resolve({ path: path.split("/") }) });
  };
  const mine = () => chain.provider.request({ method: "evm_mine", params: [] });
  const settle = async (actionId: string) => {
    for (let i = 0; i < 30; i++) {
      await runChainActionOnce(store, relayer);
      const response = await app.inject({ method: "GET", url: `/v1/chain/actions/${actionId}`, headers: { authorization: `Bearer ${credentials[0].token}` } });
      const action = response.json().action;
      if (action.status === "COMPLETED") return;
      assert.notEqual(action.status, "FAILED", response.body); await pause(50);
    }
    assert.fail("receipt outbox did not settle");
  };
  try {
    const cookies: string[] = [];
    for (const credential of credentials) {
      const login = await request("session", "", { token: credential.token }); assert.equal(login.status, 200);
      cookies.push(login.headers.get("set-cookie")!.split(";")[0]);
    }
    const [admin, operator, reader, foreign] = cookies;
    for (const cookie of [operator, reader]) assert.equal((await request("receipt-ledgers", cookie, { writer: writer.address })).status, 403);
    for (const body of [{ writer: `0x${"0".repeat(40)}` }, { writer: accounts[1].secretKey }, { writer: writer.address, privateKey: "synthetic-never-forward" }, { writer: writer.address, arguments: {} }]) assert.equal((await request("receipt-ledgers", admin, body)).status, 400);
    assert.equal((await request("receipt-ledgers", admin, { writer: writer.address }, "")).status, 400);
    assert.equal((await request("receipt-ledgers", admin, { writer: writer.address }, "csrf-attempt", "https://attacker.invalid")).status, 403);
    const registration = await request("receipt-ledgers", admin, { writer: writer.address }); assert.equal(registration.status, 202);
    const registered = (await registration.json()).ledger, key = registered.ledgerKey;
    assert.equal(registered.assurance, "LOCAL_UNANCHORED"); assert.equal(registered.txHash, null);
    assert.equal((await (await request("receipt-ledgers", admin, { writer: writer.address })).json()).ledger.ledgerKey, key);
    assert.equal((await request("receipt-ledgers", admin, { writer: new Wallet(accounts[2].secretKey).address })).status, 409);
    assert.deepEqual((await (await request("receipt-ledgers", foreign)).json()).items, []);
    await settle(registered.actionId);
    const submittedLedger = (await (await request(`receipt-ledgers/${key}`, reader)).json()).ledger;
    assert.equal(submittedLedger.assurance, "SUBMITTED"); assert.equal(submittedLedger.queueStatus, "COMPLETED"); assert.equal(submittedLedger.confirmations, 1);
    await mine();
    assert.equal((await (await request(`receipt-ledgers/${key}`, reader)).json()).ledger.assurance, "CONFIRMED");
    ledger.append({ agentIdHash: `sha256:${"a".repeat(64)}`, releaseId: id("synthetic-release"), toolName: "synthetic_private_tool_not_for_browser", operationClass: "WRITE_EXTERNAL", requestedScopeHash: `sha256:${"b".repeat(64)}`, decision: "BLOCK", policyHash: id("synthetic-policy"), phase: "ADMISSION", source: "MOCK", reasonCode: "SYNTHETIC_BLOCK", traceId: null });
    const bundle = ledger.createBatch({ fromSequence: 1, toSequence: 1 }).bundle;
    // Batch contents and signing are test-only direct API/CLI setup, never browser BFF mutations.
    const upload = await app.inject({ method: "POST", url: `/v1/receipt-ledgers/${key}/batches`, headers: { authorization: `Bearer ${credentials[1].token}` }, payload: { bundle } });
    assert.equal(upload.statusCode, 201, upload.body);
    const path = `receipt-batches/${upload.json().batch.batchId}`;
    let batch = (await (await request(path, reader)).json()).batch;
    assert.equal(batch.assurance, "LOCAL_UNANCHORED"); assert.equal(batch.confirmations, 0);
    assert.equal((await request(path, foreign)).status, 404);
    assert.equal((await request(`${path}/evidence`, reader)).status, 403);
    const evidence = await request(`${path}/evidence`, operator); assert.equal(evidence.status, 200);
    const summary = await evidence.json();
    assert.deepEqual(Object.keys(summary).sort(), ["checkedAt", "leafCount", "root", "verification"]);
    assert.equal(summary.verification, "API_VERIFIED"); assert.equal(summary.root, batch.root); assert.equal(summary.leafCount, 2);
    assert.doesNotMatch(JSON.stringify(summary), /synthetic_private_tool|requestedScopeHash|agentIdHash|files|bundle/);
    for (const blocked of [`receipt-ledgers/${key}/batches`, `${path}/anchor`]) assert.equal((await request(blocked, admin, {})).status, 404);
    assert.equal((await request(`${path}/attestation`, admin)).status, 404);
    const snapshot = await chain.provider.request({ method: "evm_snapshot", params: [] });
    const anchored = await anchorLocalReceipts({ filename, fromSequence: 1, toSequence: 1, ledgerKey: key, apiUrl, token: credentials[1].token, rpcUrl: rpc, chainId: 1337, registryAddress: deployed.registryAddress, writerKey: accounts[1].secretKey, confirmations: 2 });
    await settle(anchored.actionId);
    batch = (await (await request(path, reader)).json()).batch;
    assert.equal(batch.assurance, "SUBMITTED"); assert.equal(batch.queueStatus, "COMPLETED"); assert.equal(batch.confirmations, 1);
    assert.doesNotMatch(renderToStaticMarkup(React.createElement(ReceiptStatus, { record: batch })), /ops-badge verified/);
    await mine();
    batch = (await (await request(`receipt-ledgers/${key}/batches`, reader)).json()).items[0];
    assert.equal(batch.assurance, "CONFIRMED"); assert.equal(batch.confirmations, 2); assert.match(batch.txHash, /^0x[a-f0-9]{64}$/);
    assert.match(renderToStaticMarkup(React.createElement(ReceiptStatus, { record: batch })), /확인 수 충족/);
    await chain.provider.request({ method: "evm_revert", params: [snapshot] });
    const orphan = (await (await request(path, reader)).json()).batch; assert.equal(orphan.assurance, "ORPHANED");
    assert.match(renderToStaticMarkup(React.createElement(ReceiptStatus, { record: orphan })), /이전 확정 무효/);
    await chain.close(); closed = true;
    const unavailable = await request(path, reader); assert.equal(unavailable.status, 503);
    const failure = await unavailable.text(); assert.match(failure, /RECEIPT_CHAIN_UNAVAILABLE/); assert.doesNotMatch(failure, /CONFIRMED/);
    const html = renderToStaticMarkup(React.createElement(ReceiptRecordsView, { ledgers: [submittedLedger], batches: [batch], selected: key, error: "RECEIPT_CHAIN_UNAVAILABLE" }));
    assert.doesNotMatch(html, /CONFIRMED|COMPLETED|<table/);
  } finally {
    previous === undefined ? delete process.env.MCPSHIELD_API_URL : process.env.MCPSHIELD_API_URL = previous;
    previousOrigin === undefined ? delete process.env.MCPSHIELD_PUBLIC_ORIGIN : process.env.MCPSHIELD_PUBLIC_ORIGIN = previousOrigin;
    ledger.close(); await app.close(); if (!closed) await chain.close();
    assert.ok(resolve(directory).startsWith(resolve(tmpdir(), "mcpshield-console-receipts-")));
    await rm(directory, { recursive: true, force: true });
  }
});
