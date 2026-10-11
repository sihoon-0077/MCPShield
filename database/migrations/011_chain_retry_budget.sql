ALTER TABLE cp_chain_actions ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cp_chain_actions ADD COLUMN retry_started_at TEXT;
ALTER TABLE cp_chain_actions ADD COLUMN next_attempt_at TEXT;
