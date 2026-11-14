DROP TABLE IF EXISTS cloud.outbox, cloud.audit_log, cloud.workload_metrics, cloud.node_metrics,
    cloud.workload_events, cloud.quotas, cloud.ip_allocations, cloud.workloads, cloud.networks,
    cloud.templates, cloud.images, cloud.flavors, cloud.nodes;
DROP FUNCTION IF EXISTS cloud.audit_log_is_append_only();
