-- NetGuard attributes traffic to workloads and networks by reading this
-- service's outbox (read-only) until the event backbone relays it.
GRANT USAGE ON SCHEMA cloud TO pf_netguard;
GRANT SELECT ON cloud.outbox TO pf_netguard;
