import { JsonRpcProvider, Transaction, Wallet, ZeroAddress, keccak256 } from "ethers";
import { createReceiptAnchorRegistry, receiptAnchorDomain } from "../../../packages/contracts-sdk/src/receipts.js";
import { v2RpcRequest } from "../../../packages/contracts-sdk/src/transport.js";
import type { ChainActionKind } from "./chain-outbox.js";
import type { ControlStore } from "./control-store.js";
import { bytes32 } from "../../../packages/contracts-sdk/src/v2.js";
import { currentTraceId } from "../../../packages/telemetry/index.mjs";

export class ReceiptRelayer {
  readonly provider: JsonRpcProvider;
  readonly signer: Wallet;
  readonly registry: ReturnType<typeof createReceiptAnchorRegistry>;
  constructor(readonly rpcUrl: string, readonly registryAddress: string, readonly chainId: number, key: string, readonly confirmations = 2) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(registryAddress) || registryAddress.toLowerCase() === ZeroAddress || !Number.isSafeInteger(chainId) || chainId < 1
      || !Number.isSafeInteger(confirmations) || confirmations < 1 || confirmations > 100) throw new Error("INVALID_RECEIPT_CHAIN_CONFIG");
    this.provider = new JsonRpcProvider(v2RpcRequest(rpcUrl), undefined, { batchMaxCount: 1, cacheTimeout: -1 });
    this.signer = new Wallet(key, this.provider);
    this.registry = createReceiptAnchorRegistry(registryAddress, this.signer);
  }
  get domain() { return receiptAnchorDomain(this.chainId, this.registryAddress); }
  async network() { if ((await this.provider.getNetwork()).chainId !== BigInt(this.chainId)) throw new Error("CHAIN_ID_MISMATCH"); }
  data(kind: ChainActionKind, payload: any) {
    if (kind === "REGISTER_RECEIPT_LEDGER") return this.registry.interface.encodeFunctionData("registerLedger", [payload.ledgerKey, payload.writer]);
    if (kind === "ANCHOR_RECEIPTS") return this.registry.interface.encodeFunctionData("anchor", [payload.batch, payload.signature]);
    throw new Error("UNSUPPORTED_CHAIN_ACTION");
  }
  async alreadyApplied(_kind: ChainActionKind, _payload: any) {
    // Every claimed success must have our persisted raw transaction and a canonical receipt.
    await this.network(); return false;
  }
  async prepare(kind: ChainActionKind, payload: any, nonce: number) {
    await this.network();
    const tx = await this.signer.populateTransaction({ to: this.registryAddress, data: this.data(kind, payload), nonce, chainId: this.chainId });
    const raw = await this.signer.signTransaction(tx); return { raw, txHash: keccak256(raw) };
  }
  async observe(store: ControlStore, tenantId: string, document: Record<string, any>): Promise<Record<string, any>> {
    if (document.chainId !== this.chainId || document.registryAddress.toLowerCase() !== this.registryAddress.toLowerCase()) throw new Error("RECEIPT_DOMAIN_MISMATCH");
    const [action] = await store.query("SELECT * FROM cp_chain_actions WHERE action_id = ? AND tenant_id = ? AND chain_id = ? AND registry_address = ?", [document.actionId ?? "", tenantId, this.chainId, this.registryAddress.toLowerCase()]);
    const result = { ...document, assurance: document.assurance === "ORPHANED" ? "ORPHANED" : "LOCAL_UNANCHORED", queueStatus: action?.state ?? null,
      errorCode: action?.error_code ?? null, txHash: action?.tx_hash ?? null, confirmations: 0, requiredConfirmations: this.confirmations };
    if (!action?.tx_hash || action.state === "NEW" || action.state === "PREPARED" && !document.observedBlockHash) return result;
    await this.network();
    const receipt = await this.provider.getTransactionReceipt(action.tx_hash);
    if (!receipt) return { ...result, assurance: document.observedBlockHash ? "ORPHANED" : "SUBMITTED" };
    const block = await this.provider.getBlock(receipt.blockNumber), head = await this.provider.getBlock("latest");
    if (!block || !head) throw new Error("RECEIPT_RPC_UNAVAILABLE");
    if (block.hash !== receipt.blockHash) return { ...result, assurance: "ORPHANED" };
    const tx = await this.provider.getTransaction(action.tx_hash), payload = JSON.parse(action.payload);
    if (!tx || tx.to?.toLowerCase() !== this.registryAddress.toLowerCase() || tx.data !== this.data(action.kind, payload) || tx.value !== 0n || Number(tx.chainId) !== this.chainId) throw new Error("RECEIPT_TRANSACTION_MISMATCH");
    if (receipt.status !== 1) return { ...result, assurance: "LOCAL_UNANCHORED", queueStatus: "FAILED", errorCode: "TRANSACTION_REVERTED" };
    const depth = Math.max(0, head.number - receipt.blockNumber + 1);
    // Verify the expected contract event as well as the transaction; an address alone isn't proof of compatible code.
    const event = receipt.logs.filter((log) => log.address.toLowerCase() === this.registryAddress.toLowerCase()).map((log) => {
      try { return this.registry.interface.parseLog(log); } catch { return null; }
    }).find((log) => action.kind === "REGISTER_RECEIPT_LEDGER" ? log?.name === "LedgerRegistered" && log.args.ledgerKey === payload.ledgerKey && log.args.writer.toLowerCase() === payload.writer.toLowerCase()
      : log?.name === "ReceiptBatchAnchored" && log.args.ledgerKey === payload.batch.ledgerKey && log.args.root === payload.batch.root);
    if (!event) throw new Error("RECEIPT_EVENT_MISMATCH");
    return { ...result, assurance: depth >= this.confirmations ? "CONFIRMED" : "SUBMITTED", confirmations: depth,
      observedBlock: receipt.blockNumber, observedBlockHash: receipt.blockHash, observedAt: new Date().toISOString() };
  }
  async rewindOrphaned(store: ControlStore, tenantId: string, document: Record<string, any>) {
    if (document.assurance !== "ORPHANED" || !document.observedBlockHash || document.chainId !== this.chainId || document.registryAddress !== this.registryAddress.toLowerCase()) return false;
    const now = new Date().toISOString();
    const [action] = await store.query(`SELECT * FROM cp_chain_actions WHERE action_id = ? AND tenant_id = ? AND chain_id = ? AND registry_address = ?
      AND relayer_address = ? AND tx_hash = ? AND state = 'COMPLETED' AND (lease_owner IS NULL OR lease_expires_at <= ?)`,
    [document.actionId ?? "", tenantId, this.chainId, this.registryAddress.toLowerCase(), this.signer.address.toLowerCase(), document.txHash ?? "", now]);
    if (!action || typeof action.raw_tx !== "string" || action.raw_tx.length > 32770) return false;
    try {
      const raw = Transaction.from(action.raw_tx), payload = JSON.parse(action.payload);
      if (raw.hash !== action.tx_hash || raw.to?.toLowerCase() !== this.registryAddress.toLowerCase() || raw.from?.toLowerCase() !== action.relayer_address
        || raw.chainId !== BigInt(this.chainId) || raw.nonce !== action.nonce || raw.value !== 0n || raw.data !== this.data(action.kind, payload)) return false;
      if (action.kind === "REGISTER_RECEIPT_LEDGER") {
        if (payload.ledgerKey !== document.ledgerKey || payload.writer.toLowerCase() !== document.writer.toLowerCase()) return false;
      } else if (action.kind === "ANCHOR_RECEIPTS") {
        const b = payload.batch;
        if (b.ledgerKey !== document.ledgerKey || b.root !== document.root || b.fromSequence !== document.fromSequence || b.toSequence !== document.toSequence
          || b.previousReceiptHash !== bytes32(document.previousReceiptHash) || b.tipReceiptHash !== bytes32(document.tipReceiptHash) || b.previousBatchRoot !== document.previousBatchRoot) return false;
      } else return false;
    } catch { return false; }
    await this.network();
    const receipt = await this.provider.getTransactionReceipt(action.tx_hash);
    if (receipt) {
      const block = await this.provider.getBlock(receipt.blockNumber);
      if (!block || block.hash === receipt.blockHash) return false;
    }
    // An old orphan can fall outside the generic recent-100 reconciler. Rewind only the exact
    // previously observed signed transaction, never an in-flight lease, failed action or changed payload.
    return store.forTenant(tenantId, async (transaction) => {
      const rows = await transaction.query(`UPDATE cp_chain_actions SET state = 'PREPARED', error_code = 'REORG_RECEIPT_LOST', updated_at = ?
        WHERE action_id = ? AND tenant_id = ? AND chain_id = ? AND registry_address = ? AND relayer_address = ? AND tx_hash = ?
        AND raw_tx = ? AND payload = ? AND kind = ? AND nonce = ? AND state = 'COMPLETED' AND (lease_owner IS NULL OR lease_expires_at <= ?) RETURNING action_id`,
      [now, action.action_id, tenantId, this.chainId, this.registryAddress.toLowerCase(), this.signer.address.toLowerCase(), action.tx_hash, action.raw_tx, action.payload, action.kind, action.nonce, now]);
      if (rows.length) await transaction.event(tenantId, null, "receipt.orphan.requeued", { actionId: action.action_id, txHash: action.tx_hash, chainId: this.chainId, registryAddress: this.registryAddress }, currentTraceId());
      return rows.length === 1;
    });
  }
  close() { this.provider.destroy(); }
}
