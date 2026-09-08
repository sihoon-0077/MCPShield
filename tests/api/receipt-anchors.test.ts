import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as pause } from "node:timers/promises";
import ganache from "ganache";
import { Wallet, id } from "ethers";
import { deployReceipts } from "../../contracts/scripts/deploy-receipts.js";
import { receiptAnchorDomain, receiptBatchTypes } from "../../packages/contracts-sdk/src/receipts.js";
import { ReceiptRelayer } from "../../apps/api/src/receipt-relayer.js";
import { ControlStore } from "../../apps/api/src/control-store.js";
import { buildApp } from "../../apps/api/src/app.js";
import { runChainActionOnce, reconcileV2Actions } from "../../apps/api/src/chain-outbox.js";
import { indexReceiptAnchors } from "../../apps/indexer/src/receipt-indexer.js";
import { anchorLocalReceipts } from "../../apps/validator/src/receipt-writer.js";
// @ts-expect-error Gateway receipt implementation is shared ESM JavaScript.
import { openReceiptLedger, verifyReceiptBatch } from "../../apps/gateway/src/receipts.mjs";
// @ts-expect-error Scanner Merkle implementation is shared ESM JavaScript.
import { createEvidenceBundle } from "../../services/scanner/src/evidence.mjs";

test("real receipt API/outbox/indexer: tenant ACL, signed checkpoint, N confirmations and canonical reorg recovery", { timeout: 60000 }, async () => {
  const chain: any = ganache.server({ logging: { quiet: true }, wallet: { deterministic: true } });
  await chain.listen(0, "127.0.0.1");
  const rpc = `http://127.0.0.1:${chain.address().port}`, accounts = Object.values(chain.provider.getInitialAccounts()) as { secretKey: string }[];
  const writer = new Wallet(accounts[1].secretKey), other = new Wallet(accounts[2].secretKey);
  const deployment = await deployReceipts(rpc, accounts[0].secretKey, 1337);
  const relayer = new ReceiptRelayer(rpc, deployment.registryAddress, 1337, accounts[0].secretKey, 2);
  const dir = await mkdtemp(join(tmpdir(), "mcpshield-receipt-api-")), store = await ControlStore.open(join(dir, "control.sqlite"));
  const ledger = openReceiptLedger(join(dir, "gateway.sqlite"));
  let chainClosed = false;
  const admin = "synthetic-receipt-admin-token", operator = "synthetic-receipt-operator-token", reader = "synthetic-receipt-reader-token", foreign = "synthetic-receipt-foreign-token";
  const app = await buildApp({ adminApiToken: "unused-legacy-admin", scannerApiToken: "unused-legacy-scanner", controlPlane: { store,
    credentials: [{ token: admin, tenantId: "tenant-a", role: "admin" }, { token: operator, tenantId: "tenant-a", role: "operator" },
      { token: reader, tenantId: "tenant-a", role: "reader" }, { token: foreign, tenantId: "tenant-b", role: "admin" }],
    artifactPath: join(dir, "artifacts"), evidencePath: join(dir, "evidence"), evidenceKey: "e".repeat(64), receiptRelayer: relayer } });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const request = (method: "GET" | "POST", url: string, payload?: any, token = admin, headers = {}) => app.inject({ method, url, payload, headers: { authorization: `Bearer ${token}`, ...headers } });
  const post = async (url: string, payload: any, token = admin, headers = {}) => {
    const response = await request("POST", url, payload, token, headers); assert.ok(response.statusCode < 300, response.body); return response.json();
  };
  const mine = () => chain.provider.request({ method: "evm_mine", params: [] });
  const settle = async (actionId: string) => {
    for (let i = 0; i < 30; i++) {
      await runChainActionOnce(store, relayer);
      const action = (await request("GET", `/v1/chain/actions/${actionId}`)).json().action;
      if (action.status === "COMPLETED") return action;
      assert.notEqual(action.status, "FAILED", JSON.stringify(action)); await pause(50);
    }
    assert.fail("receipt outbox did not settle");
  };
  try {
    const fields = { agentIdHash: `sha256:${"a".repeat(64)}`, releaseId: id("synthetic-release"), toolName: "synthetic_write_tool",
      operationClass: "WRITE_EXTERNAL", requestedScopeHash: `sha256:${"b".repeat(64)}`, decision: "BLOCK", policyHash: id("synthetic-policy"), phase: "ADMISSION", source: "MOCK", reasonCode: "SYNTHETIC_BLOCK", traceId: null };
    ledger.append(fields); ledger.append(fields);
    const bundle = ledger.createBatch({ fromSequence: 1, toSequence: 2 }).bundle;
    assert.equal((await request("POST", "/v1/receipt-ledgers", { writer: writer.address }, reader)).statusCode, 403);
    const registered = (await post("/v1/receipt-ledgers", { writer: writer.address }, admin, { "idempotency-key": "synthetic-ledger-a" })).ledger;
    const ledgerKey = registered.ledgerKey, collection = `/v1/receipt-ledgers/${ledgerKey}/batches`;
    assert.equal(registered.assurance, "LOCAL_UNANCHORED");
    assert.equal((await post("/v1/receipt-ledgers", { writer: writer.address }, admin, { "idempotency-key": "synthetic-ledger-a" })).ledger.ledgerKey, ledgerKey);
    assert.equal((await request("POST", collection, { bundle })).statusCode, 409);
    await settle(registered.actionId);
    assert.equal((await request("GET", `/v1/receipt-ledgers/${ledgerKey}`)).json().ledger.assurance, "SUBMITTED");
    assert.equal((await request("POST", collection, { bundle })).statusCode, 409);
    await mine(); await indexReceiptAnchors(store, relayer);
    assert.equal((await request("GET", `/v1/receipt-ledgers/${ledgerKey}`)).json().ledger.assurance, "CONFIRMED");
    const batch = (await post(collection, { bundle }, operator)).batch, path = `/v1/receipt-batches/${batch.batchId}`;
    assert.equal(batch.assurance, "LOCAL_UNANCHORED"); assert.deepEqual(batch.sources, ["MOCK"]); assert.equal(batch.evidenceKey, undefined);
    assert.equal((await post(collection, { bundle })).batch.batchId, batch.batchId);
    const [saved] = await store.query("SELECT document FROM cp_receipt_batches WHERE batch_id = ?", [batch.batchId]);
    assert.equal((await readFile(join(dir, "evidence", `${JSON.parse(saved.document).evidenceKey}.bin`))).includes(Buffer.from("synthetic_write_tool")), false);
    assert.equal((await request("GET", path, undefined, foreign)).statusCode, 404);
    assert.equal((await request("GET", `${path}/evidence`, undefined, reader)).statusCode, 403);
    assert.equal((await request("GET", `${path}/attestation`, undefined, reader)).statusCode, 403);
    assert.equal(verifyReceiptBatch((await request("GET", `${path}/evidence`, undefined, operator)).json().bundle, batch.root), true);
    const foreignLedger = (await post("/v1/receipt-ledgers", { writer: writer.address }, foreign, { "idempotency-key": "synthetic-ledger-b" })).ledger;
    // Resolve via the shared store because the outbox GET is intentionally tenant-scoped.
    await runChainActionOnce(store, relayer); await mine(); await indexReceiptAnchors(store, relayer);
    assert.equal((await request("POST", `/v1/receipt-ledgers/${foreignLedger.ledgerKey}/batches`, { bundle }, foreign)).statusCode, 409);
    const template = (await request("GET", `${path}/attestation`, undefined, operator)).json();
    assert.deepEqual(template.types, receiptBatchTypes);
    const domain = receiptAnchorDomain(1337, deployment.registryAddress);
    const signature = await writer.signTypedData(domain, receiptBatchTypes, template.payload);
    const wrongDomain = await writer.signTypedData({ ...domain, chainId: 1 }, receiptBatchTypes, template.payload);
    assert.equal((await request("POST", `${path}/anchor`, { payload: template.payload, signature: wrongDomain })).statusCode, 400);
    assert.equal((await request("POST", `${path}/anchor`, { payload: template.payload, signature: await other.signTypedData(domain, receiptBatchTypes, template.payload) })).statusCode, 400);
    assert.equal((await request("POST", `${path}/anchor`, { payload: { ...template.payload, extra: 1 }, signature })).statusCode, 400);
    assert.equal((await request("POST", `${path}/anchor`, { payload: { ...template.payload, root: id("wrong-root") }, signature })).statusCode, 400);
    assert.equal((await request("POST", `${path}/anchor`, { payload: template.payload, signature }, foreign)).statusCode, 404);
    const snapshot = await chain.provider.request({ method: "evm_snapshot", params: [] });
    const action = (await post(`${path}/anchor`, { payload: template.payload, signature }, operator)).action;
    assert.equal(action.status, "NEW");
    assert.equal((await request("GET", path)).json().batch.assurance, "LOCAL_UNANCHORED");
    const confirmedTx = await settle(action.actionId);
    assert.equal((await request("GET", path)).json().batch.assurance, "SUBMITTED");
    await mine(); await indexReceiptAnchors(store, relayer);
    assert.equal((await request("GET", path, undefined, reader)).json().batch.assurance, "CONFIRMED");
    assert.equal((await post(`${path}/anchor`, { payload: template.payload, signature })).action.actionId, action.actionId);
    const [raw] = await store.query("SELECT raw_tx,nonce FROM cp_chain_actions WHERE action_id = ?", [action.actionId]);
    assert.ok(raw.raw_tx); assert.equal((await relayer.provider.getTransaction(confirmedTx.txHash))!.data.includes(Buffer.from("synthetic_write_tool").toString("hex")), false);
    await chain.provider.request({ method: "evm_revert", params: [snapshot] });
    await indexReceiptAnchors(store, relayer);
    assert.equal((await request("GET", path)).json().batch.assurance, "ORPHANED");
    assert.ok((await store.events("tenant-a")).some((event) => event.eventName === "receipt.batch.orphaned"));
    assert.equal(await reconcileV2Actions(store, relayer), 1);
    await chain.provider.request({ method: "evm_increaseTime", params: [2] });
    await settle(action.actionId); await mine(); await indexReceiptAnchors(store, relayer);
    const recovered = (await request("GET", path)).json().batch;
    assert.equal(recovered.assurance, "CONFIRMED"); assert.equal(recovered.txHash, confirmedTx.txHash);
    assert.equal((await store.query("SELECT raw_tx FROM cp_chain_actions WHERE action_id = ?", [action.actionId]))[0].raw_tx, raw.raw_tx);
    ledger.append(fields);
    const nextBundle = ledger.createBatch({ fromSequence: 3, toSequence: 3 }).bundle;
    const next = (await post(collection, { bundle: nextBundle })).batch;
    assert.equal(next.previousBatchRoot, batch.root);
    const invalidFiles = { ...Object.fromEntries(Object.entries(nextBundle.files).map(([path, content]) => [path, JSON.parse(content as string)])),
      "batch.json": { ...JSON.parse(nextBundle.files["batch.json"]), ledgerKey: foreignLedger.ledgerKey } };
    assert.equal((await request("POST", collection, { bundle: createEvidenceBundle(invalidFiles) })).statusCode, 400);
    const submitted = await anchorLocalReceipts({ filename: join(dir, "gateway.sqlite"), fromSequence: 3, toSequence: 3, ledgerKey,
      apiUrl: `http://127.0.0.1:${(app.server.address() as any).port}`, token: operator, rpcUrl: rpc, chainId: 1337, registryAddress: deployment.registryAddress, writerKey: accounts[1].secretKey, confirmations: 2 });
    assert.equal(submitted.assurance, "LOCAL_UNANCHORED"); assert.equal(submitted.batchId, next.batchId);
    await settle(submitted.actionId); await mine();
    assert.equal((await request("GET", `/v1/receipt-batches/${next.batchId}`)).json().batch.assurance, "CONFIRMED");
    for (let i = 0; i < 127; i++) ledger.append(fields);
    assert.equal((await post(collection, { bundle: ledger.createBatch({ fromSequence: 4, toSequence: 130 }).bundle })).batch.count, 127);
    const otherDeployment = await deployReceipts(rpc, accounts[0].secretKey, 1337), otherClient = new ReceiptRelayer(rpc, otherDeployment.registryAddress, 1337, accounts[0].secretKey, 2);
    try {
      await assert.rejects(otherClient.observe(store, "tenant-a", recovered), /DOMAIN_MISMATCH/);
      assert.equal(await runChainActionOnce(store, otherClient), false);
    } finally { otherClient.close(); }
    await chain.close(); chainClosed = true;
    assert.equal((await request("GET", path)).statusCode, 503);
  } finally { ledger.close(); await app.close(); if (!chainClosed) await chain.close(); await rm(dir, { recursive: true, force: true }); }
});
