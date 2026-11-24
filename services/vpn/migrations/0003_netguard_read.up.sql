-- NetGuard attributes traffic to VPN devices by reading this
-- service's outbox (read-only) until the event backbone relays it.
GRANT USAGE ON SCHEMA vpn TO pf_netguard;
GRANT SELECT ON vpn.outbox TO pf_netguard;
