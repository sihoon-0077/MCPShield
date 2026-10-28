import { randomBytes } from "node:crypto";
import { ZeroAddress, verifyTypedData } from "ethers";
import type { FastifyInstance } from "fastify";
import { receiptBatchTypes } from "../../../packages/contracts-sdk/src/receipts.js";
import { bytes32 } from "../../../packages/contracts-sdk/src/v2.js";
// @ts-expect-error Shared Gateway evidence verifier is ESM JavaScript.
import { verifyReceiptBatch } from "../../gateway/src/receipts.mjs";
import { chainActionId, chainActions, enqueueChainAction } from "./chain-outbox.js";
import { hash, loadEvidence, saveEvidence, type ControlOptions, type Credential } from "./control-plane.js";
import type { ControlStore } from "./control-store.js";
import type { ReceiptRelayer } from "./receipt-relayer.js";
import { currentTraceId } from "../../../packages/telemetry/index.mjs";

const fail = (code: string, statusCode = 400) => Object.assign(new Error(code), { statusCode });
const exact = (value: any, keys: string[]) => value && !Array.isArray(value) && typeof value === "object" && Object.keys(value).sort().join() === [...keys].sort().join();
export const publicReceipt = ({ evidenceKey: _key, ...record }: Record<string, any>) => record;
async function batchRecord(store: ControlStore, tenantId: string, batchId: string) {
  const [row] = await store.query("SELECT document FROM cp_receipt_batches WHERE tenant_id = ? AND batch_id = ?", [tenantId, batchId]);
  if (!row) throw fail("RECEIPT_BATCH_NOT_FOUND", 404); return JSON.parse(row.document);
}
export async function refreshReceipt(store: ControlStore, client: ReceiptRelayer, tenantId: string, recordId: string, ledger = false) {
  return store.forTenant(tenantId, async (transaction) => {
    const previous = ledger ? await transaction.get(tenantId, "receipt-ledger", recordId) : await batchRecord(transaction, tenantId, recordId);
    if (!previous) throw fail("RECEIPT_LEDGER_NOT_FOUND", 404);
    let current;
    try { current = await client.observe(transaction, tenantId, previous); }
    catch { throw fail("RECEIPT_CHAIN_UNAVAILABLE", 503); } // Never return a cached CONFIRMED during an RPC failure.
    if (ledger) await transaction.put(tenantId, "receipt-ledger", recordId, current, true);
    else await transaction.query("UPDATE cp_receipt_batches SET document = ? WHERE tenant_id = ? AND batch_id = ?", [JSON.stringify(current), tenantId, recordId]);
    if (current.assurance !== previous.assurance) await transaction.event(tenantId, null, `receipt.${ledger ? "ledger" : "batch"}.${current.assurance.toLowerCase()}`,
      { recordId, txHash: current.txHash, blockHash: current.observedBlockHash ?? null, chainId: client.chainId, registryAddress: client.registryAddress }, currentTraceId());
    return current;
  });
}

export async function registerReceiptRoutes(api: FastifyInstance, store: ControlStore, options: ControlOptions,
  authenticate: (header: string | undefined) => Credential, authorize: (identity: Credential, role: "operator" | "admin") => void) {
  const enabled = () => { if (!options.receiptRelayer) throw fail("RECEIPT_ANCHOR_NOT_CONFIGURED", 503); return options.receiptRelayer; };
  const ownLedger = async (tenantId: string, ledgerKey: string, confirmed = false) => {
    const client = enabled(), ledger = await refreshReceipt(store, client, tenantId, ledgerKey, true);
    if (confirmed && ledger.assurance !== "CONFIRMED") throw fail("RECEIPT_LEDGER_NOT_CONFIRMED", 409);
    return ledger;
  };
  const checkpoint = async (tenantId: string, ledgerKey: string) => {
    const client = enabled(), ledger = await ownLedger(tenantId, ledgerKey, true);
    const head = await client.provider.getBlock("latest"); if (!head) throw fail("RECEIPT_CHAIN_UNAVAILABLE", 503);
    const confirmedBlock = Math.max(0, head.number - client.confirmations + 1);
    const latest = await client.registry.ledgers(ledgerKey), confirmed = await client.registry.ledgers(ledgerKey, { blockTag: confirmedBlock });
    if (latest.writer.toLowerCase() !== ledger.writer.toLowerCase() || confirmed.writer.toLowerCase() !== ledger.writer.toLowerCase()
      || latest.batchRoot !== confirmed.batchRoot || latest.receiptHash !== confirmed.receiptHash || latest.lastSequence !== confirmed.lastSequence || latest.nonce !== confirmed.nonce) throw fail("RECEIPT_CHECKPOINT_NOT_CONFIRMED", 409);
    const sequence = Number(confirmed.lastSequence), nonce = Number(confirmed.nonce);
    if (!Number.isSafeInteger(sequence) || !Number.isSafeInteger(nonce)) throw fail("RECEIPT_SEQUENCE_RANGE_UNSUPPORTED", 409);
    return { ledger, sequence, nonce, receiptHash: confirmed.receiptHash, batchRoot: confirmed.batchRoot };
  };
  const prepare = async (tenantId: string, batchId: string) => {
    const client = enabled(), record = await batchRecord(store, tenantId, batchId), state = await checkpoint(tenantId, record.ledgerKey);
    const bundle = await loadEvidence(options, tenantId, record.evidenceKey, record.root);
    if (!verifyReceiptBatch(bundle, record.root)) throw fail("RECEIPT_EVIDENCE_MISMATCH", 409);
    const batch = JSON.parse(bundle.files["batch.json"]);
    if (batch.fromSequence !== state.sequence + 1 || bytes32(batch.previousReceiptHash) !== state.receiptHash || record.previousBatchRoot !== state.batchRoot) throw fail("RECEIPT_CHECKPOINT_MISMATCH", 409);
    return { record, writer: state.ledger.writer, payload: { ledgerKey: record.ledgerKey, root: record.root, fromSequence: batch.fromSequence, toSequence: batch.toSequence,
      previousReceiptHash: bytes32(batch.previousReceiptHash), tipReceiptHash: bytes32(batch.tipReceiptHash), previousBatchRoot: state.batchRoot, nonce: state.nonce, deadline: Math.floor(Date.now() / 1000) + 600 } };
  };
  api.post("/receipt-ledgers", async (request, reply) => {
    const user = authenticate(request.headers.authorization); authorize(user, "admin");
    const body = request.body as any, client = enabled(), key = request.headers["idempotency-key"];
    if (!exact(body, ["writer"]) || !/^0x[0-9a-fA-F]{40}$/.test(body.writer) || body.writer.toLowerCase() === ZeroAddress) throw fail("INVALID_RECEIPT_WRITER");
    if (typeof key !== "string" || !key.trim() || key.length > 256) throw fail("IDEMPOTENCY_KEY_REQUIRED");
    await client.network();
    if ((await client.registry.admin()).toLowerCase() !== client.signer.address.toLowerCase()) throw fail("RECEIPT_RELAYER_NOT_ADMIN", 503);
    const requestHash = hash({ writer: body.writer.toLowerCase(), domain: client.domain });
    const ledger = await store.forTenant(user.tenantId, async (transaction) => {
      const prior = await transaction.get(user.tenantId, "receipt-ledger-request", hash(key));
      if (prior) {
        if (prior.requestHash !== requestHash) throw fail("IDEMPOTENCY_CONFLICT", 409);
        return (await transaction.get(user.tenantId, "receipt-ledger", prior.ledgerKey))!;
      }
      const ledgerKey = `0x${randomBytes(32).toString("hex")}`, writer = body.writer.toLowerCase();
      const action = await enqueueChainAction(transaction, client, user.tenantId, "REGISTER_RECEIPT_LEDGER", { ledgerKey, writer });
      const record = { ledgerKey, writer, chainId: client.chainId, registryAddress: client.registryAddress.toLowerCase(), actionId: action.actionId,
        assurance: "LOCAL_UNANCHORED", createdAt: new Date().toISOString(), governance: "CONFIGURED_WRITER" };
      await transaction.put(user.tenantId, "receipt-ledger", ledgerKey, record);
      await transaction.put(user.tenantId, "receipt-ledger-request", hash(key), { ledgerKey, requestHash }); return record;
    });
    return reply.code(202).send({ ledger: await ownLedger(user.tenantId, ledger.ledgerKey) });
  });
  api.get("/receipt-ledgers", async (request) => {
    const user = authenticate(request.headers.authorization), items = [];
    for (const ledger of await store.list(user.tenantId, "receipt-ledger")) items.push(await ownLedger(user.tenantId, ledger.ledgerKey));
    return { items };
  });
  api.get("/receipt-ledgers/:ledgerKey", async (request) => ({ ledger: await ownLedger(authenticate(request.headers.authorization).tenantId, (request.params as any).ledgerKey) }));
  api.post("/receipt-ledgers/:ledgerKey/batches", async (request, reply) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    const body = request.body as any, client = enabled(), ledgerKey = (request.params as any).ledgerKey;
    if (!exact(body, ["bundle"]) || !verifyReceiptBatch(body.bundle, body.bundle?.manifest?.root)) throw fail("INVALID_RECEIPT_BATCH");
    const root = bytes32(body.bundle.manifest.root), batch = JSON.parse(body.bundle.files["batch.json"]);
    if (!exact(batch, ["schemaVersion", "fromSequence", "toSequence", "count", "previousReceiptHash", "tipReceiptHash"])) throw fail("INVALID_RECEIPT_BATCH");
    const ledger = await ownLedger(user.tenantId, ledgerKey, true);
    const [existing] = await store.query("SELECT tenant_id,ledger_key,document FROM cp_receipt_batches WHERE root = ?", [root]);
    if (existing) {
      if (existing.tenant_id !== user.tenantId || existing.ledger_key !== ledgerKey) throw fail("RECEIPT_ROOT_ALREADY_CLAIMED", 409);
      return reply.code(200).send({ batch: publicReceipt(await refreshReceipt(store, client, user.tenantId, JSON.parse(existing.document).batchId)), idempotent: true });
    }
    const state = await checkpoint(user.tenantId, ledgerKey);
    if (batch.fromSequence !== state.sequence + 1 || bytes32(batch.previousReceiptHash) !== state.receiptHash) throw fail("RECEIPT_CHECKPOINT_MISMATCH", 409);
    const evidenceKey = await saveEvidence(options, user.tenantId, body.bundle), batchId = hash({ domain: client.domain, ledgerKey, root });
    const record = { batchId, ledgerKey, root, ...batch, previousBatchRoot: state.batchRoot, evidenceKey,
      chainId: ledger.chainId, registryAddress: ledger.registryAddress, assurance: "LOCAL_UNANCHORED", actionId: null, createdAt: new Date().toISOString(),
      sources: [...new Set(Object.entries(body.bundle.files).filter(([path]) => path !== "batch.json").map(([, content]) => JSON.parse(content as string).source))].sort(), claim: "CHECKPOINT_ONLY_NOT_EXECUTION_PROOF" };
    try {
      await store.query("INSERT INTO cp_receipt_batches(batch_id,tenant_id,ledger_key,root,chain_id,registry_address,from_sequence,document,created_at) VALUES(?,?,?,?,?,?,?,?,?)", [batchId, user.tenantId, ledgerKey, root, client.chainId, client.registryAddress.toLowerCase(), batch.fromSequence, JSON.stringify(record), record.createdAt]);
    } catch (error: any) { if (error.code === "23505" || /UNIQUE/.test(error.message)) throw fail("RECEIPT_ROOT_OR_RANGE_ALREADY_CLAIMED", 409); throw error; }
    await store.event(user.tenantId, null, "receipt.batch.stored", { batchId, root });
    return reply.code(201).send({ batch: publicReceipt(record) });
  });
  api.get("/receipt-ledgers/:ledgerKey/batches", async (request) => {
    const user = authenticate(request.headers.authorization), ledgerKey = (request.params as any).ledgerKey;
    await ownLedger(user.tenantId, ledgerKey); const items = [];
    for (const row of await store.query("SELECT batch_id FROM cp_receipt_batches WHERE tenant_id = ? AND ledger_key = ? ORDER BY created_at DESC LIMIT 250", [user.tenantId, ledgerKey])) items.push(publicReceipt(await refreshReceipt(store, enabled(), user.tenantId, row.batch_id)));
    return { items };
  });
  api.get("/receipt-batches/:batchId", async (request) => ({ batch: publicReceipt(await refreshReceipt(store, enabled(), authenticate(request.headers.authorization).tenantId, (request.params as any).batchId)) }));
  api.get("/receipt-batches/:batchId/evidence", async (request) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    const record = await batchRecord(store, user.tenantId, (request.params as any).batchId);
    const bundle = await loadEvidence(options, user.tenantId, record.evidenceKey, record.root);
    if (!verifyReceiptBatch(bundle, record.root)) throw fail("RECEIPT_EVIDENCE_MISMATCH", 409); return { bundle };
  });
  api.get("/receipt-batches/:batchId/attestation", async (request) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    const prepared = await prepare(user.tenantId, (request.params as any).batchId);
    return { domain: enabled().domain, types: receiptBatchTypes, payload: prepared.payload, writer: prepared.writer, evidenceUrl: `/v1/receipt-batches/${prepared.record.batchId}/evidence` };
  });
  api.post("/receipt-batches/:batchId/anchor", async (request, reply) => {
    const user = authenticate(request.headers.authorization); authorize(user, "operator");
    const client = enabled(), body = request.body as any, batchId = (request.params as any).batchId;
    if (!exact(body, ["payload", "signature"]) || !exact(body.payload, receiptBatchTypes.ReceiptBatch.map((field) => field.name)) || !/^0x[0-9a-fA-F]{130}$/.test(body.signature)) throw fail("INVALID_RECEIPT_ATTESTATION");
    const record = await batchRecord(store, user.tenantId, batchId);
    await ownLedger(user.tenantId, record.ledgerKey, true);
    if (body.payload.root !== record.root || body.payload.ledgerKey !== record.ledgerKey) throw fail("RECEIPT_BINDING_MISMATCH");
    const payload = { batch: body.payload, signature: body.signature }, actionId = chainActionId(client, user.tenantId, "ANCHOR_RECEIPTS", payload);
    const previous = (await chainActions(store, user.tenantId, actionId))[0];
    if (previous) return reply.code(202).send({ action: previous, idempotent: true });
    const prepared = await prepare(user.tenantId, batchId), { deadline: _expected, ...expected } = prepared.payload, { deadline, ...received } = body.payload;
    const now = Math.floor(Date.now() / 1000);
    if (hash(expected) !== hash(received) || !Number.isSafeInteger(deadline) || deadline < now || deadline > now + 3600) throw fail("RECEIPT_BINDING_MISMATCH");
    let writer;
    try { writer = verifyTypedData(client.domain, receiptBatchTypes, body.payload, body.signature); } catch { throw fail("INVALID_RECEIPT_SIGNATURE"); }
    if (writer.toLowerCase() !== prepared.writer.toLowerCase()) throw fail("RECEIPT_WRITER_MISMATCH");
    const action = await store.forTenant(user.tenantId, async (transaction) => {
      const current = await batchRecord(transaction, user.tenantId, batchId);
      if (current.actionId) {
        const prior = (await chainActions(transaction, user.tenantId, current.actionId))[0];
        if (prior && prior.status !== "FAILED") throw fail("RECEIPT_ANCHOR_ALREADY_QUEUED", 409);
      }
      const queued = await enqueueChainAction(transaction, client, user.tenantId, "ANCHOR_RECEIPTS", payload);
      await transaction.query("UPDATE cp_receipt_batches SET document = ? WHERE batch_id = ? AND tenant_id = ?", [JSON.stringify({ ...current, actionId: queued.actionId }), batchId, user.tenantId]); return queued;
    });
    return reply.code(202).send({ action });
  });
}
