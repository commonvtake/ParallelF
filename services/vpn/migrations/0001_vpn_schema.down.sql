DROP TABLE IF EXISTS vpn.outbox, vpn.audit_log, vpn.peer_stats, vpn.policies, vpn.activations,
    vpn.devices, vpn.gateways, vpn.state;
DROP FUNCTION IF EXISTS vpn.audit_log_is_append_only();
