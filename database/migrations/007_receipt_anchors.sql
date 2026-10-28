-- A root cannot be reassigned to another tenant, ledger or deployment.
CREATE TABLE IF NOT EXISTS cp_receipt_batches (
  batch_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, ledger_key TEXT NOT NULL,
  root TEXT NOT NULL UNIQUE, chain_id INTEGER NOT NULL, registry_address TEXT NOT NULL,
  from_sequence INTEGER NOT NULL, document TEXT NOT NULL, created_at TEXT NOT NULL,
  UNIQUE(chain_id, registry_address, ledger_key, from_sequence)
);
CREATE INDEX IF NOT EXISTS cp_receipt_tenant_ledger ON cp_receipt_batches(tenant_id,ledger_key,created_at);
