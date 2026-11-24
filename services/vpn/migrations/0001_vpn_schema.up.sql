-- ParallelF VPN: gateways, devices (WireGuard peers), activations, access
-- policies, peer statistics, the audit trail and the event outbox.
--
-- The server stores only public keys. Optional pre-shared keys are stored
-- encrypted (AES-256-GCM with a key-encryption key from a secret).

-- The desired-state revision: every change that alters what a gateway must
-- configure increments it, and agents long-poll for a newer one.
CREATE TABLE vpn.state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision  bigint  NOT NULL DEFAULT 1
);
INSERT INTO vpn.state DEFAULT VALUES;

CREATE TABLE vpn.gateways (
    id               uuid        PRIMARY KEY,
    name             text        NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9.-]{0,62}$'),
    token_hash       bytea       NOT NULL UNIQUE,
    public_key       text        NOT NULL CHECK (length(public_key) = 44),
    endpoint         text        NOT NULL,
    listen_port      integer     NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    agent_version    text        NOT NULL DEFAULT '',
    status           text        NOT NULL DEFAULT 'READY' CHECK (status IN ('READY', 'NOT_READY')),
    applied_revision bigint      NOT NULL DEFAULT 0,
    apply_error      text        NOT NULL DEFAULT '',
    registered_at    timestamptz NOT NULL,
    last_seen_at     timestamptz NOT NULL
);

CREATE TABLE vpn.devices (
    id                uuid        PRIMARY KEY,
    owner_subject     text        NOT NULL,
    owner_name        text        NOT NULL DEFAULT '',
    name              text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{1,38}[a-z0-9]$'),
    public_key        text        NOT NULL CHECK (length(public_key) = 44),
    address           inet        NOT NULL CHECK (family(address) = 4 AND masklen(address) = 32),
    groups            text[]      NOT NULL DEFAULT '{}',
    psk_ciphertext    bytea,
    state             text        NOT NULL DEFAULT 'PENDING'
                                  CHECK (state IN ('PENDING', 'ENROLLED', 'REVOKED', 'EXPIRED')),
    active_until      timestamptz,
    expires_at        timestamptz NOT NULL,
    created_at        timestamptz NOT NULL,
    ended_at          timestamptz,
    last_handshake_at timestamptz,
    endpoint          text        NOT NULL DEFAULT '',
    rx_bytes          bigint      NOT NULL DEFAULT 0,
    tx_bytes          bigint      NOT NULL DEFAULT 0,
    connected         boolean     NOT NULL DEFAULT false,
    CHECK ((state IN ('REVOKED', 'EXPIRED')) = (ended_at IS NOT NULL))
);
-- Live devices hold their key, address and name exclusively.
CREATE UNIQUE INDEX devices_live_key ON vpn.devices (public_key) WHERE state IN ('PENDING', 'ENROLLED');
CREATE UNIQUE INDEX devices_live_address ON vpn.devices (address) WHERE state IN ('PENDING', 'ENROLLED');
CREATE UNIQUE INDEX devices_live_name ON vpn.devices (owner_subject, name) WHERE state IN ('PENDING', 'ENROLLED');
CREATE INDEX devices_owner ON vpn.devices (owner_subject, created_at);

CREATE TABLE vpn.activations (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id  uuid        NOT NULL REFERENCES vpn.devices (id),
    subject    text        NOT NULL,
    started_at timestamptz NOT NULL,
    until      timestamptz NOT NULL,
    ended_at   timestamptz,
    ended_by   text        NOT NULL DEFAULT ''
);
CREATE INDEX activations_device ON vpn.activations (device_id, started_at);

CREATE TABLE vpn.policies (
    id           uuid        PRIMARY KEY,
    name         text        NOT NULL UNIQUE CHECK (name ~ '^[a-z][a-z0-9-]{1,38}[a-z0-9]$'),
    priority     integer     NOT NULL CHECK (priority BETWEEN 1 AND 10000),
    action       text        NOT NULL CHECK (action IN ('allow', 'deny')),
    groups       text[]      NOT NULL CHECK (cardinality(groups) BETWEEN 1 AND 16),
    destinations text[]      NOT NULL CHECK (cardinality(destinations) BETWEEN 1 AND 32),
    protocol     text        NOT NULL CHECK (protocol IN ('tcp', 'udp', 'icmp', 'any')),
    ports        text[]      NOT NULL DEFAULT '{}',
    description  text        NOT NULL DEFAULT '',
    created_by   text        NOT NULL,
    created_at   timestamptz NOT NULL
);

CREATE TABLE vpn.peer_stats (
    device_id uuid        NOT NULL REFERENCES vpn.devices (id),
    ts        timestamptz NOT NULL,
    rx_bytes  bigint      NOT NULL,
    tx_bytes  bigint      NOT NULL,
    PRIMARY KEY (device_id, ts)
);

-- Audit trail (same layout and append-only rules as every service) --------
CREATE TABLE vpn.audit_log (
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
CREATE INDEX audit_log_resource ON vpn.audit_log (resource_type, resource_id);
CREATE FUNCTION vpn.audit_log_is_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'vpn.audit_log is append-only';
END
$$;
CREATE TRIGGER audit_log_no_update_or_delete BEFORE UPDATE OR DELETE ON vpn.audit_log
    FOR EACH ROW EXECUTE FUNCTION vpn.audit_log_is_append_only();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON vpn.audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION vpn.audit_log_is_append_only();

-- Transactional outbox ------------------------------------------------------
CREATE TABLE vpn.outbox (
    id           uuid        PRIMARY KEY,
    subject      text        NOT NULL,
    event_type   text        NOT NULL,
    payload      bytea       NOT NULL,
    headers      jsonb       NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz
);
CREATE INDEX outbox_unpublished ON vpn.outbox (created_at) WHERE published_at IS NULL;

-- Runtime privileges ----------------------------------------------------------
GRANT SELECT, UPDATE ON vpn.state TO pf_vpn;
GRANT SELECT, INSERT, UPDATE, DELETE ON vpn.gateways, vpn.devices, vpn.activations, vpn.policies TO pf_vpn;
GRANT SELECT, INSERT, DELETE ON vpn.peer_stats TO pf_vpn;
GRANT SELECT, INSERT ON vpn.audit_log TO pf_vpn;
GRANT SELECT, INSERT, UPDATE ON vpn.outbox TO pf_vpn;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA vpn TO pf_vpn;
