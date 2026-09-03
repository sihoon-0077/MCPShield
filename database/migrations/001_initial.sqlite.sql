PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS releases (
  release_id TEXT PRIMARY KEY,
  artifact_digest TEXT NOT NULL,
  tool_surface_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'UNVERIFIED'
    CHECK (status IN ('UNVERIFIED', 'VERIFIED', 'QUARANTINED', 'REVOKED')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY,
  release_id TEXT NOT NULL REFERENCES releases(release_id),
  schema_version TEXT NOT NULL CHECK (schema_version = '1.0.0'),
  artifact_digest TEXT NOT NULL,
  tool_surface_hash TEXT NOT NULL,
  scan_status TEXT NOT NULL,
  findings_json TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  source TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS validator_votes (
  release_id TEXT NOT NULL REFERENCES releases(release_id),
  validator_address TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('PASS', 'FAIL', 'ABSTAIN')),
  evidence_hash TEXT NOT NULL,
  scan_id TEXT NOT NULL REFERENCES scans(scan_id),
  nonce INTEGER NOT NULL,
  signature TEXT NOT NULL,
  tx_hash TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY (release_id, validator_address)
);

CREATE TABLE IF NOT EXISTS chain_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  release_id TEXT NOT NULL REFERENCES releases(release_id),
  event_name TEXT NOT NULL,
  status TEXT,
  tx_hash TEXT,
  block_number INTEGER,
  log_index INTEGER,
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS chain_events_log_uidx
  ON chain_events(tx_hash, log_index) WHERE tx_hash IS NOT NULL AND log_index IS NOT NULL;

CREATE TABLE IF NOT EXISTS validator_nonces (
  validator_address TEXT PRIMARY KEY,
  next_nonce INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS indexer_checkpoints (
  name TEXT PRIMARY KEY,
  block_number INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_operations (
  operation_id TEXT PRIMARY KEY,
  operation_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING', 'SUBMITTED', 'COMPLETED', 'FAILED')),
  tx_hash TEXT,
  payload_json TEXT NOT NULL,
  error TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS scans_release_id_idx ON scans(release_id);
CREATE INDEX IF NOT EXISTS chain_events_release_id_idx ON chain_events(release_id, id);
