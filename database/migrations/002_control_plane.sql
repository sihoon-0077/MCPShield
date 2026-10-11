-- Portable PostgreSQL/SQLite control-plane tables. Legacy /api projections are separate.
CREATE TABLE IF NOT EXISTS cp_records (
  tenant_id TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL,
  document TEXT NOT NULL, created_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, kind, id)
);
CREATE TABLE IF NOT EXISTS cp_scans (
  scan_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, release_id TEXT NOT NULL,
  policy_hash TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL,
  request_json TEXT NOT NULL, state TEXT NOT NULL CHECK (state IN ('QUEUED','RUNNING','COMPLETED','DEAD_LETTER')),
  stage TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL,
  lease_owner TEXT, lease_expires_at TEXT, next_attempt_at TEXT NOT NULL,
  trace_id TEXT NOT NULL, last_error TEXT, result_json TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS cp_scan_queue ON cp_scans(state, next_attempt_at, created_at);
CREATE INDEX IF NOT EXISTS cp_scan_release ON cp_scans(tenant_id, release_id, created_at);
CREATE TABLE IF NOT EXISTS cp_events (
  event_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, release_id TEXT,
  event_name TEXT NOT NULL, payload TEXT NOT NULL, trace_id TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS cp_event_release ON cp_events(tenant_id, release_id, created_at);
