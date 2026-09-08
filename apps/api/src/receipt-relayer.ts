import { JsonRpcProvider, Wallet, ZeroAddress, keccak256 } from "ethers";
import { createReceiptAnchorRegistry, receiptAnchorDomain } from "../../../packages/contracts-sdk/src/receipts.js";
import { v2RpcRequest } from "../../../packages/contracts-sdk/src/transport.js";
import type { ChainActionKind } from "./chain-outbox.js";
import type { ControlStore } from "./control-store.js";

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
  close() { this.provider.destroy(); }
}
