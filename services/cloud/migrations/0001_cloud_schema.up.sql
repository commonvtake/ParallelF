-- Schema "cloud", owned by pf_cloud_owner. The runtime role pf_cloud gets
-- only the table privileges it needs (granted at the end) and never DDL.
--
-- Desired state lives here. Node agents converge their hosts to it and
-- report what they observe; nothing about a workload exists only in memory.

-- Compute hosts running pf-node-agent ---------------------------------------
CREATE TABLE cloud.nodes (
    id                  uuid        PRIMARY KEY,
    name                text        NOT NULL UNIQUE
                        CHECK (name ~ '^[a-z0-9][a-z0-9.-]{0,62}$'),
    -- READY while the agent syncs; NOT_READY after the heartbeat expires.
    status              text        NOT NULL DEFAULT 'READY'
                        CHECK (status IN ('READY', 'NOT_READY')),
    schedulable         boolean     NOT NULL DEFAULT true,   -- false = cordoned
    token_hash          bytea       NOT NULL,                -- sha256 of the node credential
    agent_version       text        NOT NULL DEFAULT '',
    kvm                 boolean     NOT NULL DEFAULT false,  -- can run VMs
    docker              boolean     NOT NULL DEFAULT false,  -- can run containers
    hypervisor          text        NOT NULL DEFAULT '',
    cpu_count           integer     NOT NULL DEFAULT 0 CHECK (cpu_count >= 0),
    memory_mib          bigint      NOT NULL DEFAULT 0 CHECK (memory_mib >= 0),
    disk_gib            bigint      NOT NULL DEFAULT 0 CHECK (disk_gib >= 0),
    -- Held back for the host OS and the platform itself; never scheduled.
    reserved_cpus       integer     NOT NULL DEFAULT 0 CHECK (reserved_cpus >= 0),
    reserved_memory_mib bigint      NOT NULL DEFAULT 0 CHECK (reserved_memory_mib >= 0),
    reserved_disk_gib   bigint      NOT NULL DEFAULT 0 CHECK (reserved_disk_gib >= 0),
    registered_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX nodes_token_hash ON cloud.nodes (token_hash);

-- Catalogue ------------------------------------------------------------------
CREATE TABLE cloud.flavors (
    id         uuid    PRIMARY KEY,
    name       text    NOT NULL UNIQUE CHECK (name ~ '^[a-z][a-z0-9.-]{1,30}$'),
    vcpus      integer NOT NULL CHECK (vcpus BETWEEN 1 AND 64),
    memory_mib integer NOT NULL CHECK (memory_mib BETWEEN 64 AND 262144),
    disk_gib   integer NOT NULL CHECK (disk_gib BETWEEN 1 AND 2048)
);

CREATE TABLE cloud.images (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    kind        text NOT NULL CHECK (kind IN ('vm', 'container')),
    -- VM: https URL of a qcow2 image. Container: OCI reference.
    source      text NOT NULL,
    -- VM images are verified against this digest before first use.
    sha256      text CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    os          text NOT NULL DEFAULT '',
    CHECK (kind = 'container' OR (sha256 IS NOT NULL AND source LIKE 'https://%'))
);

-- A template is an immutable, versioned recipe: image + default flavor +
-- provisioning settings. Changing a recipe means adding a new version.
CREATE TABLE cloud.templates (
    id                uuid    PRIMARY KEY,
    name              text    NOT NULL CHECK (name ~ '^[a-z][a-z0-9.-]{1,40}$'),
    version           integer NOT NULL CHECK (version >= 1),
    kind              text    NOT NULL CHECK (kind IN ('vm', 'container')),
    description       text    NOT NULL DEFAULT '',
    image_id          uuid    NOT NULL REFERENCES cloud.images (id),
    default_flavor_id uuid    NOT NULL REFERENCES cloud.flavors (id),
    -- VM: cloud-config document (JSON object) merged with per-workload keys.
    cloud_config      jsonb   NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(cloud_config) = 'object'),
    -- VM: the guest configures its address itself (needed on lab networks).
    static_network    boolean NOT NULL DEFAULT false,
    -- Container: command and the capabilities added back after dropping all.
    command           jsonb   NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(command) = 'array'),
    cap_add           jsonb   NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(cap_add) = 'array'),
    deprecated        boolean NOT NULL DEFAULT false,
    UNIQUE (name, version)
);

-- Networks -------------------------------------------------------------------
CREATE TABLE cloud.networks (
    id          uuid        PRIMARY KEY,
    project_id  uuid        NOT NULL,                 -- core.projects.id (no cross-schema FK)
    name        text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{1,38}[a-z0-9]$'),
    -- nat: outbound internet through the host. isolated: no route off the
    -- network. lab: isolated and the host has no address on it either.
    kind        text        NOT NULL CHECK (kind IN ('nat', 'isolated', 'lab')),
    cidr        cidr        NOT NULL CHECK (family(cidr) = 4 AND masklen(cidr) BETWEEN 16 AND 27),
    gateway_ip  inet,
    bridge_name text        NOT NULL UNIQUE CHECK (bridge_name ~ '^pfbr-[0-9a-f]{8}$'),
    created_by  text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz,
    CHECK ((kind = 'lab') = (gateway_ip IS NULL)),
    CHECK (gateway_ip IS NULL OR gateway_ip << cidr),
    -- All networks share one host routing table, so live CIDRs may not overlap.
    EXCLUDE USING gist (cidr inet_ops WITH &&) WHERE (deleted_at IS NULL)
);
CREATE UNIQUE INDEX networks_live_name ON cloud.networks (project_id, name) WHERE deleted_at IS NULL;

-- Workloads ------------------------------------------------------------------
CREATE TABLE cloud.workloads (
    id                  uuid        PRIMARY KEY,
    project_id          uuid        NOT NULL,
    name                text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{1,38}[a-z0-9]$'),
    kind                text        NOT NULL CHECK (kind IN ('vm', 'container')),
    template_id         uuid        NOT NULL REFERENCES cloud.templates (id),
    flavor_id           uuid        NOT NULL REFERENCES cloud.flavors (id),
    network_id          uuid        NOT NULL REFERENCES cloud.networks (id),
    node_id             uuid        REFERENCES cloud.nodes (id),
    -- Resources reserved at admission (copied from the flavor).
    vcpus               integer     NOT NULL CHECK (vcpus >= 1),
    memory_mib          integer     NOT NULL CHECK (memory_mib >= 64),
    disk_gib            integer     NOT NULL CHECK (disk_gib >= 1),
    ip                  inet        NOT NULL,
    mac                 macaddr     NOT NULL,
    desired_state       text        NOT NULL CHECK (desired_state IN ('running', 'stopped', 'deleted')),
    state               text        NOT NULL DEFAULT 'PENDING'
                        CHECK (state IN ('PENDING', 'SCHEDULED', 'PROVISIONING', 'RUNNING', 'STOPPING',
                                         'STOPPED', 'UNKNOWN', 'DELETING', 'DELETED', 'ERROR')),
    -- Incremented on every change of desired state; the agent reports the
    -- generation it has applied (Kubernetes-style convergence tracking).
    generation          bigint      NOT NULL DEFAULT 1,
    observed_generation bigint      NOT NULL DEFAULT 0,
    status_message      text        NOT NULL DEFAULT '',
    spec                jsonb       NOT NULL DEFAULT '{}',   -- ssh keys, env
    created_by          text        NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    state_changed_at    timestamptz NOT NULL DEFAULT now(),
    deleted_at          timestamptz,
    CHECK ((state = 'DELETED') = (deleted_at IS NOT NULL))
);
CREATE UNIQUE INDEX workloads_live_name ON cloud.workloads (project_id, name) WHERE deleted_at IS NULL;
CREATE INDEX workloads_node ON cloud.workloads (node_id) WHERE deleted_at IS NULL;
CREATE INDEX workloads_pending ON cloud.workloads (created_at) WHERE state = 'PENDING';
CREATE INDEX workloads_network ON cloud.workloads (network_id) WHERE deleted_at IS NULL;

-- One row per address in use. Released when the workload is deleted.
CREATE TABLE cloud.ip_allocations (
    network_id  uuid    NOT NULL REFERENCES cloud.networks (id),
    ip          inet    NOT NULL,
    workload_id uuid    NOT NULL UNIQUE REFERENCES cloud.workloads (id),
    mac         macaddr NOT NULL UNIQUE,
    PRIMARY KEY (network_id, ip)
);

-- Per-project limits. Projects without a row get the configured default.
CREATE TABLE cloud.quotas (
    project_id     uuid        PRIMARY KEY,
    max_vcpus      integer     NOT NULL CHECK (max_vcpus >= 0),
    max_memory_mib integer     NOT NULL CHECK (max_memory_mib >= 0),
    max_disk_gib   integer     NOT NULL CHECK (max_disk_gib >= 0),
    max_workloads  integer     NOT NULL CHECK (max_workloads >= 0),
    updated_by     text        NOT NULL,
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- History shown on a workload's page.
CREATE TABLE cloud.workload_events (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workload_id uuid        NOT NULL REFERENCES cloud.workloads (id),
    ts          timestamptz NOT NULL DEFAULT now(),
    type        text        NOT NULL,
    message     text        NOT NULL DEFAULT ''
);
CREATE INDEX workload_events_by_workload ON cloud.workload_events (workload_id, ts);

-- Utilisation samples reported by agents, kept for 24 hours.
CREATE TABLE cloud.node_metrics (
    node_id          uuid        NOT NULL REFERENCES cloud.nodes (id) ON DELETE CASCADE,
    ts               timestamptz NOT NULL,
    cpu_percent      real        NOT NULL,
    memory_used_mib  bigint      NOT NULL,
    memory_total_mib bigint      NOT NULL,
    disk_used_gib    real        NOT NULL,
    disk_total_gib   real        NOT NULL,
    PRIMARY KEY (node_id, ts)
);

CREATE TABLE cloud.workload_metrics (
    workload_id     uuid        NOT NULL REFERENCES cloud.workloads (id),
    ts              timestamptz NOT NULL,
    cpu_percent     real        NOT NULL,
    memory_used_mib bigint      NOT NULL,
    PRIMARY KEY (workload_id, ts)
);

-- Append-only, hash-chained audit trail ----------------------------------------
CREATE TABLE cloud.audit_log (
    seq           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id            uuid        NOT NULL UNIQUE,
    ts            timestamptz NOT NULL,
    actor_type    text        NOT NULL CHECK (actor_type IN ('user', 'agent', 'system')),
    actor_id      text        NOT NULL,
    actor_name    text        NOT NULL DEFAULT '',
    action        text        NOT NULL,              -- e.g. cloud.workloads.delete
    resource_type text        NOT NULL DEFAULT '',
    resource_id   text        NOT NULL DEFAULT '',
    project_id    uuid,
    outcome       text        NOT NULL CHECK (outcome IN ('success', 'denied', 'failed')),
    request_id    text        NOT NULL DEFAULT '',
    details       jsonb       NOT NULL DEFAULT '{}',
    prev_hash     bytea       NOT NULL,              -- hash of the previous row (genesis: 32 zero bytes)
    hash          bytea       NOT NULL               -- sha256(prev_hash || canonical row)
);
CREATE INDEX audit_log_ts ON cloud.audit_log USING brin (ts);
CREATE INDEX audit_log_resource ON cloud.audit_log (resource_type, resource_id);

CREATE FUNCTION cloud.audit_log_is_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'cloud.audit_log is append-only';
END
$$;
CREATE TRIGGER audit_log_no_update_or_delete BEFORE UPDATE OR DELETE ON cloud.audit_log
    FOR EACH ROW EXECUTE FUNCTION cloud.audit_log_is_append_only();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON cloud.audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION cloud.audit_log_is_append_only();

-- Transactional outbox (same contract as core.outbox) ------------------------
CREATE TABLE cloud.outbox (
    id           uuid        PRIMARY KEY,
    subject      text        NOT NULL,
    event_type   text        NOT NULL,
    payload      bytea       NOT NULL,
    headers      jsonb       NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz
);
CREATE INDEX outbox_unpublished ON cloud.outbox (created_at) WHERE published_at IS NULL;

-- Runtime privileges -----------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON
    cloud.nodes, cloud.networks, cloud.workloads, cloud.ip_allocations, cloud.quotas,
    cloud.node_metrics, cloud.workload_metrics
TO pf_cloud;
GRANT SELECT ON cloud.flavors, cloud.images, cloud.templates TO pf_cloud;
GRANT SELECT, INSERT, DELETE ON cloud.workload_events TO pf_cloud;
GRANT SELECT, INSERT ON cloud.audit_log TO pf_cloud;
GRANT SELECT, INSERT, UPDATE ON cloud.outbox TO pf_cloud;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA cloud TO pf_cloud;
