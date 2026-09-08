import type { ControlStore } from "../../api/src/control-store.js";
import type { ReceiptRelayer } from "../../api/src/receipt-relayer.js";
import { refreshReceipt } from "../../api/src/receipt-control.js";

export async function indexReceiptAnchors(store: ControlStore, client: ReceiptRelayer) {
  let observed = 0;
  // ponytail: O(n) canonical-receipt audit, pages bound memory. Add indexed log ranges if history polling becomes costly.
  // API reads independently recheck the receipt, so an indexer outage can never make an old CONFIRMED authoritative.
  let ledgerCursor = "";
  while (true) {
    const page = await store.query("SELECT tenant_id,id,document FROM cp_records WHERE kind = 'receipt-ledger' AND id > ? ORDER BY id LIMIT 100", [ledgerCursor]);
    if (!page.length) break;
    for (const ledger of page) {
      const document = JSON.parse(ledger.document);
      if (document.chainId === client.chainId && document.registryAddress === client.registryAddress.toLowerCase()) {
        await refreshReceipt(store, client, ledger.tenant_id, ledger.id, true); observed++;
      }
    }
    ledgerCursor = page.at(-1)!.id;
  }
  let cursor = "";
  while (true) {
    const page = await store.query("SELECT batch_id,tenant_id FROM cp_receipt_batches WHERE chain_id = ? AND registry_address = ? AND batch_id > ? ORDER BY batch_id LIMIT 100", [client.chainId, client.registryAddress.toLowerCase(), cursor]);
    if (!page.length) break;
    for (const batch of page) { await refreshReceipt(store, client, batch.tenant_id, batch.batch_id); observed++; }
    cursor = page.at(-1)!.batch_id;
  }
  return { observed };
}
