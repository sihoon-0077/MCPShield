import { JsonRpcProvider, Wallet } from "ethers";
import { pathToFileURL } from "node:url";
import { createReceiptAnchorRegistry, receiptAnchorDomain, receiptBatchTypes } from "../../../packages/contracts-sdk/src/receipts.js";
import { bytes32 } from "../../../packages/contracts-sdk/src/v2.js";
import { boundedServiceRequest, checkedServiceUrl, v2RpcRequest } from "../../../packages/contracts-sdk/src/transport.js";
// @ts-expect-error Gateway receipt implementation is shared ESM JavaScript.
import { openReceiptLedger } from "../../gateway/src/receipts.mjs";

export async function anchorLocalReceipts(options: { filename: string; fromSequence: number; toSequence: number; ledgerKey: string;
  apiUrl: string; token: string; rpcUrl: string; chainId: number; registryAddress: string; writerKey: string; confirmations: number }) {
  if (!/^0x[0-9a-f]{64}$/.test(options.ledgerKey) || !/^0x[0-9a-fA-F]{40}$/.test(options.registryAddress) || !Number.isSafeInteger(options.chainId) || options.chainId < 1
    || !Number.isSafeInteger(options.confirmations) || options.confirmations < 1 || options.confirmations > 100) throw new Error("RECEIPT_WRITER_CONFIG_REQUIRED");
  const ledger = openReceiptLedger(options.filename);
  let local;
  try { local = ledger.createBatch(options); } finally { ledger.close(); }
  const provider = new JsonRpcProvider(v2RpcRequest(options.rpcUrl), undefined, { batchMaxCount: 1, cacheTimeout: -1 }), wallet = new Wallet(options.writerKey);
  try {
    if ((await provider.getNetwork()).chainId !== BigInt(options.chainId)) throw new Error("CHAIN_ID_MISMATCH");
    const registry = createReceiptAnchorRegistry(options.registryAddress, provider), head = await provider.getBlock("latest");
    if (!head) throw new Error("RECEIPT_CHAIN_UNAVAILABLE");
    const latest = await registry.ledgers(options.ledgerKey), state = await registry.ledgers(options.ledgerKey, { blockTag: Math.max(0, head.number - options.confirmations + 1) });
    if (state.writer.toLowerCase() !== wallet.address.toLowerCase() || latest.writer !== state.writer || latest.batchRoot !== state.batchRoot || latest.nonce !== state.nonce
      || local.batch.fromSequence !== Number(state.lastSequence) + 1 || bytes32(local.batch.previousReceiptHash) !== state.receiptHash || !Number.isSafeInteger(Number(state.nonce))) throw new Error("RECEIPT_WRITER_CHECKPOINT_MISMATCH");
    // The signing inputs come exclusively from the local verified ledger, pinned config and direct confirmed RPC.
    // No API-returned domain, types, deadline or payload is ever signed.
    const payload = { ledgerKey: options.ledgerKey, root: bytes32(local.bundle.manifest.root), fromSequence: local.batch.fromSequence, toSequence: local.batch.toSequence,
      previousReceiptHash: bytes32(local.batch.previousReceiptHash), tipReceiptHash: bytes32(local.batch.tipReceiptHash), previousBatchRoot: state.batchRoot,
      nonce: Number(state.nonce), deadline: Math.floor(Date.now() / 1000) + 600 };
    const base = checkedServiceUrl(options.apiUrl);
    const post = async (path: string, body: any) => {
      const result = await boundedServiceRequest(new URL(path, base).href, { method: "POST", headers: { authorization: `Bearer ${options.token}`, "content-type": "application/json" }, body: JSON.stringify(body) });
      if (result.statusCode < 200 || result.statusCode >= 300) throw new Error(`RECEIPT_API_HTTP_${result.statusCode}`); return JSON.parse(result.body.toString());
    };
    const { batch } = await post(`/v1/receipt-ledgers/${options.ledgerKey}/batches`, { bundle: local.bundle });
    if (batch.root !== payload.root || batch.ledgerKey !== options.ledgerKey || !/^0x[0-9a-f]{64}$/.test(batch.batchId)) throw new Error("RECEIPT_API_BINDING_MISMATCH");
    const signature = await wallet.signTypedData(receiptAnchorDomain(options.chainId, options.registryAddress), receiptBatchTypes, payload);
    const { action } = await post(`/v1/receipt-batches/${batch.batchId}/anchor`, { payload, signature });
    // Queued is not an on-chain confirmation. Read the batch endpoint after the worker processes the outbox.
    return { mode: "SINGLE_WRITER_CHECKPOINT", assurance: "LOCAL_UNANCHORED", batchId: batch.batchId, root: payload.root, actionId: action.actionId, queueStatus: action.status };
  } finally { provider.destroy(); }
}
async function main() {
  const env = process.env;
  if (!process.argv.includes("--submit") || !env.RECEIPT_LEDGER_PATH || !env.RECEIPT_LEDGER_KEY || !env.CONTROL_API_URL || !env.CONTROL_API_TOKEN || !env.CONTROL_RECEIPT_RPC_URL
    || !env.CONTROL_RECEIPT_CHAIN_ID || !env.CONTROL_RECEIPT_REGISTRY_ADDRESS || !env.RECEIPT_WRITER_KEY) throw new Error("RECEIPT_WRITER_CONFIG_AND_SUBMIT_FLAG_REQUIRED");
  console.log(JSON.stringify(await anchorLocalReceipts({ filename: env.RECEIPT_LEDGER_PATH, ledgerKey: env.RECEIPT_LEDGER_KEY, fromSequence: Number(env.RECEIPT_FROM_SEQUENCE), toSequence: Number(env.RECEIPT_TO_SEQUENCE),
    apiUrl: env.CONTROL_API_URL, token: env.CONTROL_API_TOKEN, rpcUrl: env.CONTROL_RECEIPT_RPC_URL, chainId: Number(env.CONTROL_RECEIPT_CHAIN_ID), registryAddress: env.CONTROL_RECEIPT_REGISTRY_ADDRESS,
    writerKey: env.RECEIPT_WRITER_KEY, confirmations: Number(env.CONTROL_RECEIPT_CONFIRMATIONS ?? 2) })));
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch(() => { console.error("RECEIPT_WRITER_FAILED"); process.exitCode = 1; });
