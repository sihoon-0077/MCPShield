ALTER TABLE cp_chain_actions ADD COLUMN registry_address TEXT;
CREATE INDEX cp_chain_domain_queue ON cp_chain_actions(chain_id,relayer_address,registry_address,state,created_at);
