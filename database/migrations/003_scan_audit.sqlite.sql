CREATE TRIGGER IF NOT EXISTS cp_scan_created AFTER INSERT ON cp_scans BEGIN
  INSERT INTO cp_events(event_id, tenant_id, release_id, event_name, payload, trace_id, created_at)
  VALUES(lower(hex(randomblob(16))), NEW.tenant_id, NEW.release_id, 'scan.state.changed',
    json_object('scanId',NEW.scan_id,'status',NEW.state,'attempts',NEW.attempts), NEW.trace_id, NEW.created_at);
END;
CREATE TRIGGER IF NOT EXISTS cp_scan_changed AFTER UPDATE ON cp_scans WHEN OLD.state != NEW.state BEGIN
  INSERT INTO cp_events(event_id, tenant_id, release_id, event_name, payload, trace_id, created_at)
  VALUES(lower(hex(randomblob(16))), NEW.tenant_id, NEW.release_id, 'scan.state.changed',
    json_object('scanId',NEW.scan_id,'previousStatus',OLD.state,'status',NEW.state,'attempts',NEW.attempts), NEW.trace_id, NEW.updated_at);
END;
