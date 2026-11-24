-- ParallelF NetGuard: sensors, normalized telemetry, the attribution of
-- addresses to Cloud workloads and VPN devices, alerts, incidents with
-- append-only evidence, signed discovery scopes, the audit trail and the
-- event outbox.

CREATE TABLE netguard.sensors (
    id            uuid        PRIMARY KEY,
    name          text        NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9.-]{0,62}$'),
    token_hash    bytea       NOT NULL UNIQUE,
    agent_version text        NOT NULL DEFAULT '',
    engine        text        NOT NULL DEFAULT '',
    interfaces    text[]      NOT NULL DEFAULT '{}',
    engine_error  text        NOT NULL DEFAULT '',
    events_total  bigint      NOT NULL DEFAULT 0,
    registered_at timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL
);

-- Telemetry. raw_sha256 (of the source line) makes re-delivery idempotent
-- and lets an analyst prove an event came from a given EVE record.
CREATE TABLE netguard.events (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sensor_id    uuid        NOT NULL REFERENCES netguard.sensors (id) ON DELETE CASCADE,
    ts           timestamptz NOT NULL,
    received_at  timestamptz NOT NULL,
    kind         text        NOT NULL CHECK (kind IN ('flow', 'dns', 'http', 'tls', 'alert', 'anomaly', 'discovery')),
    iface        text        NOT NULL DEFAULT '',
    src_ip       inet,
    src_port     integer     CHECK (src_port BETWEEN 0 AND 65535),
    dst_ip       inet,
    dst_port     integer     CHECK (dst_port BETWEEN 0 AND 65535),
    proto        text        NOT NULL DEFAULT '',
    community_id text        NOT NULL DEFAULT '',
    app_proto    text        NOT NULL DEFAULT '',
    details      jsonb       NOT NULL DEFAULT '{}',
    raw_sha256   bytea       NOT NULL UNIQUE CHECK (length(raw_sha256) = 32)
);
CREATE INDEX events_ts ON netguard.events USING brin (ts);
CREATE INDEX events_src ON netguard.events (src_ip, ts);
CREATE INDEX events_dst ON netguard.events (dst_ip, ts);
CREATE INDEX events_community ON netguard.events (community_id) WHERE community_id <> '';

-- Networks known from Cloud events (lab networks matter to detection).
CREATE TABLE netguard.networks (
    id         uuid        PRIMARY KEY,
    project_id uuid,
    name       text        NOT NULL,
    kind       text        NOT NULL,
    cidr       cidr        NOT NULL,
    created_at timestamptz NOT NULL,
    deleted_at timestamptz
);

-- Who held an address when: from Cloud and VPN events, and from
-- configured infrastructure addresses.
CREATE TABLE netguard.attributions (
    id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip            inet        NOT NULL,
    kind          text        NOT NULL CHECK (kind IN ('workload', 'vpn_device', 'network_gateway', 'infrastructure')),
    entity_id     text        NOT NULL,
    name          text        NOT NULL DEFAULT '',
    project_id    uuid,
    owner_subject text        NOT NULL DEFAULT '',
    valid_from    timestamptz NOT NULL,
    valid_to      timestamptz,
    source_event  text        NOT NULL DEFAULT '',
    UNIQUE (kind, entity_id, ip, valid_from)
);
CREATE INDEX attributions_ip ON netguard.attributions (ip, valid_from);
CREATE UNIQUE INDEX attributions_open ON netguard.attributions (kind, entity_id, ip) WHERE valid_to IS NULL;

-- Outbox rows of other services already applied (consumption is
-- idempotent and tolerant of rows that commit out of created_at order).
CREATE TABLE netguard.consumed (
    source   text        NOT NULL,
    event_id uuid        NOT NULL,
    subject  text        NOT NULL,
    applied  timestamptz NOT NULL,
    PRIMARY KEY (source, event_id)
);

-- Every address seen on a monitored network.
CREATE TABLE netguard.assets (
    ip            inet        PRIMARY KEY,
    first_seen_at timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    first_iface   text        NOT NULL DEFAULT '',
    events        bigint      NOT NULL DEFAULT 0,
    open_ports    integer[]   NOT NULL DEFAULT '{}'
);

-- Processing positions (detection over events).
CREATE TABLE netguard.cursors (
    name     text   PRIMARY KEY,
    position bigint NOT NULL DEFAULT 0
);
INSERT INTO netguard.cursors (name) VALUES ('detect');

CREATE TABLE netguard.incidents (
    id          uuid        PRIMARY KEY,
    title       text        NOT NULL CHECK (length(title) BETWEEN 3 AND 200),
    severity    text        NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    status      text        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved')),
    summary     text        NOT NULL DEFAULT '',
    created_by  text        NOT NULL,
    created_at  timestamptz NOT NULL,
    updated_at  timestamptz NOT NULL,
    resolved_at timestamptz,
    CHECK ((status = 'resolved') = (resolved_at IS NOT NULL))
);

CREATE TABLE netguard.alerts (
    id              uuid        PRIMARY KEY,
    detector        text        NOT NULL,
    rule_id         text        NOT NULL,
    severity        text        NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    title           text        NOT NULL,
    src_ip          inet,
    dst_ip          inet,
    dedupe_key      text        NOT NULL,
    status          text        NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'closed', 'suppressed')),
    count           bigint      NOT NULL DEFAULT 1,
    first_seen_at   timestamptz NOT NULL,
    last_seen_at    timestamptz NOT NULL,
    first_event_id  bigint,
    last_event_id   bigint,
    details         jsonb       NOT NULL DEFAULT '{}',
    attribution     jsonb       NOT NULL DEFAULT '{}',
    incident_id     uuid        REFERENCES netguard.incidents (id),
    status_reason   text        NOT NULL DEFAULT '',
    status_by       text        NOT NULL DEFAULT '',
    suppressed_until timestamptz,
    CHECK ((status = 'suppressed') = (suppressed_until IS NOT NULL))
);
-- One live alert per dedupe key: repeats increase its count.
CREATE UNIQUE INDEX alerts_live ON netguard.alerts (dedupe_key) WHERE status IN ('open', 'acknowledged', 'suppressed');
CREATE INDEX alerts_seen ON netguard.alerts (last_seen_at DESC);
CREATE INDEX alerts_incident ON netguard.alerts (incident_id) WHERE incident_id IS NOT NULL;

CREATE TABLE netguard.incident_timeline (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id uuid        NOT NULL REFERENCES netguard.incidents (id),
    ts          timestamptz NOT NULL,
    actor       text        NOT NULL,
    kind        text        NOT NULL CHECK (kind IN ('opened', 'note', 'status', 'alert_linked', 'evidence')),
    body        text        NOT NULL DEFAULT '',
    ref         text        NOT NULL DEFAULT ''
);
CREATE INDEX incident_timeline_incident ON netguard.incident_timeline (incident_id, id);

-- Evidence is append-only: what was collected cannot be changed, and its
-- digest is recorded when it is added.
CREATE TABLE netguard.evidence (
    id          uuid        PRIMARY KEY,
    incident_id uuid        NOT NULL REFERENCES netguard.incidents (id),
    kind        text        NOT NULL CHECK (kind IN ('event', 'alert', 'note', 'file')),
    name        text        NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    media_type  text        NOT NULL,
    content     bytea       NOT NULL CHECK (length(content) <= 1048576),
    sha256      bytea       NOT NULL CHECK (length(sha256) = 32),
    ref         text        NOT NULL DEFAULT '',
    added_by    text        NOT NULL,
    added_at    timestamptz NOT NULL
);
CREATE INDEX evidence_incident ON netguard.evidence (incident_id, added_at);
CREATE FUNCTION netguard.evidence_is_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'netguard.evidence is append-only';
END
$$;
CREATE TRIGGER evidence_no_update_or_delete BEFORE UPDATE OR DELETE ON netguard.evidence
    FOR EACH ROW EXECUTE FUNCTION netguard.evidence_is_append_only();
CREATE TRIGGER evidence_no_truncate BEFORE TRUNCATE ON netguard.evidence
    FOR EACH STATEMENT EXECUTE FUNCTION netguard.evidence_is_append_only();

-- Discovery scopes: what an owner authorised, signed as issued.
CREATE TABLE netguard.scopes (
    id                 uuid        PRIMARY KEY,
    name               text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{1,38}[a-z0-9]$'),
    cidrs              cidr[]      NOT NULL,
    techniques         text[]      NOT NULL,
    ports              integer[]   NOT NULL DEFAULT '{}',
    rate_pps           integer     NOT NULL CHECK (rate_pps BETWEEN 1 AND 100),
    authorization_note text        NOT NULL CHECK (length(authorization_note) BETWEEN 10 AND 1000),
    issued_at          timestamptz NOT NULL,
    valid_until        timestamptz NOT NULL CHECK (valid_until > issued_at),
    document           text        NOT NULL,
    signature          text        NOT NULL,
    created_by         text        NOT NULL,
    revoked_at         timestamptz,
    revoked_by         text        NOT NULL DEFAULT ''
);
CREATE INDEX scopes_live ON netguard.scopes (valid_until) WHERE revoked_at IS NULL;

-- Audit trail (same layout and append-only rules as every service) --------
CREATE TABLE netguard.audit_log (
    seq           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id            uuid        NOT NULL UNIQUE,
    ts            timestamptz NOT NULL,
    actor_type    text        NOT NULL CHECK (actor_type IN ('user', 'agent', 'system')),
    actor_id      text        NOT NULL,
    actor_name    text        NOT NULL DEFAULT '',
    action        text        NOT NULL,
    resource_type text        NOT NULL DEFAULT '',
    resource_id   text        NOT NULL DEFAULT '',
    project_id    uuid,
    outcome       text        NOT NULL CHECK (outcome IN ('success', 'denied', 'failed')),
    request_id    text        NOT NULL DEFAULT '',
    details       jsonb       NOT NULL DEFAULT '{}',
    prev_hash     bytea       NOT NULL,
    hash          bytea       NOT NULL
);
CREATE INDEX audit_log_resource ON netguard.audit_log (resource_type, resource_id);
CREATE FUNCTION netguard.audit_log_is_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'netguard.audit_log is append-only';
END
$$;
CREATE TRIGGER audit_log_no_update_or_delete BEFORE UPDATE OR DELETE ON netguard.audit_log
    FOR EACH ROW EXECUTE FUNCTION netguard.audit_log_is_append_only();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON netguard.audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION netguard.audit_log_is_append_only();

-- Transactional outbox ------------------------------------------------------
CREATE TABLE netguard.outbox (
    id           uuid        PRIMARY KEY,
    subject      text        NOT NULL,
    event_type   text        NOT NULL,
    payload      bytea       NOT NULL,
    headers      jsonb       NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz
);
CREATE INDEX outbox_unpublished ON netguard.outbox (created_at) WHERE published_at IS NULL;

-- Runtime privileges ----------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON netguard.sensors, netguard.networks, netguard.attributions,
    netguard.assets, netguard.alerts, netguard.incidents TO pf_netguard;
GRANT SELECT, INSERT, DELETE ON netguard.events, netguard.consumed TO pf_netguard;
GRANT SELECT, UPDATE ON netguard.cursors TO pf_netguard;
GRANT SELECT, INSERT, UPDATE ON netguard.scopes TO pf_netguard;
GRANT SELECT, INSERT ON netguard.incident_timeline, netguard.evidence, netguard.audit_log TO pf_netguard;
GRANT SELECT, INSERT, UPDATE ON netguard.outbox TO pf_netguard;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA netguard TO pf_netguard;
