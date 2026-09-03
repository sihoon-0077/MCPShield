CREATE TYPE release_status AS ENUM (
  'UNVERIFIED', 'VERIFIED', 'QUARANTINED', 'REVOKED'
);
CREATE TYPE scan_status AS ENUM (
  'QUEUED', 'RUNNING', 'PASSED', 'FAILED', 'INCONCLUSIVE'
);
CREATE TYPE validator_decision AS ENUM ('PASS', 'FAIL', 'ABSTAIN');

CREATE TABLE releases (
  release_id TEXT PRIMARY KEY,
  artifact_digest TEXT NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
  tool_surface_hash TEXT NOT NULL CHECK (tool_surface_hash ~ '^0x[0-9a-f]{64}$'),
  status release_status NOT NULL DEFAULT 'UNVERIFIED',
  registration_tx_hash TEXT,
  registration_block_number BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE scans (
  scan_id UUID PRIMARY KEY,
  release_id TEXT NOT NULL REFERENCES releases(release_id),
  schema_version TEXT NOT NULL CHECK (schema_version = '1.0.0'),
  artifact_digest TEXT NOT NULL,
  tool_surface_hash TEXT NOT NULL,
  scan_status scan_status NOT NULL,
  findings JSONB NOT NULL,
  evidence_hash TEXT NOT NULL CHECK (evidence_hash ~ '^0x[0-9a-f]{64}$'),
  source TEXT NOT NULL CHECK (source IN ('LIVE', 'MOCK', 'REPLAY')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE validator_votes (
  release_id TEXT NOT NULL REFERENCES releases(release_id),
  validator_address TEXT NOT NULL,
  decision validator_decision NOT NULL,
  evidence_hash TEXT NOT NULL,
  scan_id UUID REFERENCES scans(scan_id),
  nonce BIGINT NOT NULL,
  signature TEXT NOT NULL,
  tx_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (release_id, validator_address)
);

CREATE TABLE chain_events (
  id BIGSERIAL PRIMARY KEY,
  release_id TEXT NOT NULL REFERENCES releases(release_id),
  event_name TEXT NOT NULL,
  status release_status,
  tx_hash TEXT,
  block_number BIGINT,
  log_index INTEGER,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX scans_release_id_idx ON scans(release_id);
CREATE INDEX chain_events_release_id_idx ON chain_events(release_id, id);
CREATE UNIQUE INDEX chain_events_log_uidx ON chain_events(tx_hash, log_index)
  WHERE tx_hash IS NOT NULL AND log_index IS NOT NULL;

CREATE TABLE validator_nonces (
  validator_address TEXT PRIMARY KEY,
  next_nonce BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE indexer_checkpoints (
  name TEXT PRIMARY KEY,
  block_number BIGINT NOT NULL,
  block_hash TEXT NOT NULL
);

CREATE TABLE pending_operations (
  operation_id TEXT PRIMARY KEY,
  operation_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING', 'SUBMITTED', 'COMPLETED', 'FAILED')),
  tx_hash TEXT,
  payload JSONB NOT NULL,
  error TEXT,
  claimed_at TIMESTAMPTZ NOT NULL,
  lease_expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
