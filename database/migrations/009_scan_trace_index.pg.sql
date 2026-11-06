CREATE INDEX IF NOT EXISTS cp_scan_report_trace ON cp_scans
  (tenant_id, release_id, policy_hash, (result_json::jsonb->>'reportRoot'), updated_at DESC, scan_id)
  WHERE state = 'COMPLETED';
