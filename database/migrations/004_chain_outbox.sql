CREATE TABLE IF NOT EXISTS cp_chain_actions (
  action_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, release_id TEXT,
  kind TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'NEW',
  chain_id INTEGER NOT NULL, relayer_address TEXT NOT NULL, nonce INTEGER,
  raw_tx TEXT, tx_hash TEXT, error_code TEXT, lease_owner TEXT, lease_expires_at TEXT, trace_parent TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(chain_id, relayer_address, nonce)
);
CREATE INDEX IF NOT EXISTS cp_chain_queue ON cp_chain_actions(state, created_at);
CREATE TABLE IF NOT EXISTS cp_relayer_leases (
  chain_id INTEGER NOT NULL, relayer_address TEXT NOT NULL, lease_owner TEXT, lease_expires_at TEXT,
  PRIMARY KEY(chain_id, relayer_address)
);
CREATE TABLE IF NOT EXISTS cp_v2_blocks (
  chain_id INTEGER NOT NULL, registry_address TEXT NOT NULL, block_number INTEGER NOT NULL, block_hash TEXT NOT NULL,
  PRIMARY KEY(chain_id, registry_address, block_number)
);
CREATE TABLE IF NOT EXISTS cp_v2_events (
  chain_id INTEGER NOT NULL, registry_address TEXT NOT NULL, block_number INTEGER NOT NULL, block_hash TEXT NOT NULL,
  transaction_hash TEXT NOT NULL, log_index INTEGER NOT NULL, release_id TEXT, event_name TEXT NOT NULL, payload TEXT NOT NULL,
  PRIMARY KEY(chain_id, registry_address, transaction_hash, log_index)
);
