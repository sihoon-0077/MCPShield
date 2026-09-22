CREATE OR REPLACE FUNCTION cp_scan_audit() RETURNS trigger AS $$
BEGIN
  INSERT INTO cp_events(event_id, tenant_id, release_id, event_name, payload, trace_id, created_at)
  VALUES(md5(random()::text || clock_timestamp()::text), NEW.tenant_id, NEW.release_id, 'scan.state.changed',
    json_build_object('scanId',NEW.scan_id,'status',NEW.state,'attempts',NEW.attempts)::text, NEW.trace_id, NEW.updated_at);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS cp_scan_created ON cp_scans;
CREATE TRIGGER cp_scan_created AFTER INSERT ON cp_scans FOR EACH ROW EXECUTE FUNCTION cp_scan_audit();
DROP TRIGGER IF EXISTS cp_scan_changed ON cp_scans;
CREATE TRIGGER cp_scan_changed AFTER UPDATE ON cp_scans FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state) EXECUTE FUNCTION cp_scan_audit();
