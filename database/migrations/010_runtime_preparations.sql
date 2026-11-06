-- A preparation has a source identity; its resulting scan has a different, immutable identity.
CREATE TABLE IF NOT EXISTS cp_preparations (
  preparation_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, source_release_id TEXT NOT NULL,
  policy_hash TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL,
  request_json TEXT NOT NULL, config_hash TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('QUEUED','RUNNING','COMPLETED','DEAD_LETTER')),
  attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3,
  lease_owner TEXT, lease_expires_at TEXT, next_attempt_at TEXT NOT NULL,
  trace_id TEXT NOT NULL, last_error TEXT, result_json TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE (tenant_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS cp_preparation_queue ON cp_preparations(state,next_attempt_at,created_at);
CREATE INDEX IF NOT EXISTS cp_preparation_tenant ON cp_preparations(tenant_id,created_at);
