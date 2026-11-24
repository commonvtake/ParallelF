DROP TABLE IF EXISTS netguard.outbox, netguard.audit_log, netguard.scopes, netguard.evidence, netguard.incident_timeline,
    netguard.alerts, netguard.incidents, netguard.cursors, netguard.assets, netguard.consumed, netguard.attributions,
    netguard.networks, netguard.events, netguard.sensors;
DROP FUNCTION IF EXISTS netguard.evidence_is_append_only(), netguard.audit_log_is_append_only();
