CREATE TABLE IF NOT EXISTS cp_scan_request_keys (
  tenant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL,
  scan_id TEXT NOT NULL REFERENCES cp_scans(scan_id) ON DELETE CASCADE,
  PRIMARY KEY(tenant_id, idempotency_key)
);
