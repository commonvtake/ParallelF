// Package store keeps pf-netguardd's state in PostgreSQL (schema netguard).
//
// Ingest transactions serialise on an advisory lock, so event ids become
// visible in order and the detection cursor never skips a row that commits
// late.
package store

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/commonvtake/parallelf/pkg/auditlog/pgaudit"
	"github.com/commonvtake/parallelf/pkg/ngsensor"
	"github.com/commonvtake/parallelf/pkg/outbox"
	"github.com/commonvtake/parallelf/services/netguard/internal/domain"
)

// Encoder turns domain changes into outbox events.
type Encoder interface {
	SensorRegistered(s domain.Sensor) (outbox.Event, error)
	AlertRaised(a domain.Alert) (outbox.Event, error)
	AlertStatusChanged(a domain.Alert, from, actor string, at time.Time) (outbox.Event, error)
	IncidentChanged(i domain.Incident, from, actor string, at time.Time) (outbox.Event, error)
	EvidenceAdded(e domain.Evidence) (outbox.Event, error)
	ScopeChanged(s domain.Scope, change, actor string, at time.Time) (outbox.Event, error)
}

// Options configure the store.
type Options struct {
	Encoder Encoder
	NewID   func() string
	Now     func() time.Time
	// Monitored are the ranges ParallelF owns (the VPN tunnel and the Cloud
	// address space): new-device detection and scope issuing are limited to
	// them.
	Monitored []netip.Prefix
	// ScopeKey signs discovery scopes.
	ScopeKey ed25519.PrivateKey
}

// Postgres is the store.
type Postgres struct {
	pool  *pgxpool.Pool
	opts  Options
	audit *pgaudit.Log
}

// Open connects to the database.
func Open(ctx context.Context, url string, opts Options) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	cfg.MaxConns = 10
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Postgres{pool: pool, opts: opts, audit: pgaudit.New("netguard", opts.NewID, opts.Now)}, nil
}

// Close releases the pool.
func (s *Postgres) Close() { s.pool.Close() }

// Ping checks the connection.
func (s *Postgres) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Postgres) now() time.Time { return s.opts.Now().UTC().Truncate(time.Microsecond) }

func (s *Postgres) inTx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func pgCode(err error) (string, string) {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code, pg.ConstraintName
	}
	return "", ""
}

func (s *Postgres) emit(ctx context.Context, tx pgx.Tx, evt outbox.Event, err error) error {
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	return outbox.Insert(ctx, tx, "netguard", evt)
}

func (s *Postgres) appendAudit(ctx context.Context, tx pgx.Tx, actor domain.Actor, action, resourceType, resourceID string, details map[string]string) error {
	return s.audit.Append(ctx, tx, pgaudit.Record{
		Actor:  pgaudit.Actor{Type: actor.Type, ID: actor.ID, Name: actor.Name, RequestID: actor.RequestID},
		Action: action, ResourceType: resourceType, ResourceID: resourceID, Details: details,
	})
}

// ListAudit returns audit entries, newest first.
func (s *Postgres) ListAudit(ctx context.Context, f pgaudit.Filter) ([]pgaudit.Entry, error) {
	return s.audit.List(ctx, s.pool, f)
}

// VerifyAudit recomputes the hash chain.
func (s *Postgres) VerifyAudit(ctx context.Context) (pgaudit.Verification, error) {
	return s.audit.Verify(ctx, s.pool)
}

func jsonMap(raw []byte) map[string]string {
	out := map[string]string{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// --- Sensors -------------------------------------------------------------------------

const sensorColumns = `s.id::text, s.name, s.agent_version, s.engine, s.interfaces, s.engine_error, s.events_total,
	s.registered_at, s.last_seen_at`

func (s *Postgres) scanSensor(row pgx.Row) (domain.Sensor, error) {
	var x domain.Sensor
	err := row.Scan(&x.ID, &x.Name, &x.AgentVersion, &x.Engine, &x.Interfaces, &x.EngineError, &x.EventsTotal, &x.RegisteredAt, &x.LastSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Sensor{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Sensor{}, fmt.Errorf("scan sensor: %w", err)
	}
	x.RegisteredAt, x.LastSeenAt = x.RegisteredAt.UTC(), x.LastSeenAt.UTC()
	x.Status = "reporting"
	if s.opts.Now().Sub(x.LastSeenAt) > domain.SensorSilentAfter {
		x.Status = "silent"
	}
	if x.Interfaces == nil {
		x.Interfaces = []string{}
	}
	return x, nil
}

// RegisterSensor adds a sensor or, for a known name, replaces its
// credential (a reinstalled host).
func (s *Postgres) RegisterSensor(ctx context.Context, r domain.SensorRegistration) (domain.Sensor, error) {
	var x domain.Sensor
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		now := s.now()
		var err error
		x, err = s.scanSensor(tx.QueryRow(ctx, `
			INSERT INTO netguard.sensors AS s (id, name, token_hash, agent_version, engine, registered_at, last_seen_at)
			VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $6)
			ON CONFLICT (name) DO UPDATE SET token_hash = EXCLUDED.token_hash, agent_version = EXCLUDED.agent_version,
				engine = EXCLUDED.engine, last_seen_at = EXCLUDED.last_seen_at
			RETURNING `+sensorColumns, s.opts.NewID(), r.Name, r.TokenHash, r.AgentVersion, r.Engine, now))
		if err != nil {
			return fmt.Errorf("register sensor: %w", err)
		}
		evt, eerr := s.opts.Encoder.SensorRegistered(x)
		if err := s.emit(ctx, tx, evt, eerr); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, domain.Actor{Type: "agent", ID: x.ID, Name: x.Name}, "network.sensors.register", "sensor", x.ID,
			map[string]string{"engine": x.Engine, "agent_version": x.AgentVersion})
	})
	return x, err
}

// AuthenticateSensor finds the sensor holding a credential.
func (s *Postgres) AuthenticateSensor(ctx context.Context, tokenHash []byte) (domain.Sensor, error) {
	x, err := s.scanSensor(s.pool.QueryRow(ctx, `SELECT `+sensorColumns+` FROM netguard.sensors s WHERE s.token_hash = $1`, tokenHash))
	if errors.Is(err, domain.ErrNotFound) {
		return domain.Sensor{}, domain.ErrUnauthorizedSens
	}
	return x, err
}

// ListSensors returns every sensor.
func (s *Postgres) ListSensors(ctx context.Context) ([]domain.Sensor, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+sensorColumns+` FROM netguard.sensors s ORDER BY s.name`)
	if err != nil {
		return nil, fmt.Errorf("list sensors: %w", err)
	}
	defer rows.Close()
	out := []domain.Sensor{}
	for rows.Next() {
		x, err := s.scanSensor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// GetSensor returns one sensor.
func (s *Postgres) GetSensor(ctx context.Context, id string) (domain.Sensor, error) {
	return s.scanSensor(s.pool.QueryRow(ctx, `SELECT `+sensorColumns+` FROM netguard.sensors s WHERE s.id = $1::text::uuid`, id))
}

// DeleteSensor removes a silent sensor and its telemetry.
func (s *Postgres) DeleteSensor(ctx context.Context, id string, actor domain.Actor) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		x, err := s.scanSensor(tx.QueryRow(ctx, `SELECT `+sensorColumns+` FROM netguard.sensors s WHERE s.id = $1::text::uuid FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if x.Status == "reporting" {
			return domain.ErrSensorActive
		}
		if _, err := tx.Exec(ctx, `DELETE FROM netguard.sensors WHERE id = $1::text::uuid`, id); err != nil {
			return fmt.Errorf("delete sensor: %w", err)
		}
		return s.appendAudit(ctx, tx, actor, "network.sensors.delete", "sensor", id, map[string]string{"name": x.Name})
	})
}

// Ingest stores a batch from a sensor and records its heartbeat. Repeated
// events (same source line) are ignored. It returns how many were new.
func (s *Postgres) Ingest(ctx context.Context, sensor domain.Sensor, req ngsensor.IngestRequest) (int, error) {
	n := len(req.Events)
	ts := make([]time.Time, n)
	kind, iface, src, dst, proto, cid, app, details, raw := make([]string, n), make([]string, n), make([]string, n), make([]string, n),
		make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	sport, dport := make([]int32, n), make([]int32, n)
	for i, e := range req.Events {
		ts[i], kind[i], iface[i], src[i], dst[i], proto[i], cid[i], app[i], raw[i] = e.Time.UTC(), e.Kind, e.Interface, e.SrcIP, e.DstIP, e.Proto, e.CommunityID, e.AppProto, e.RawSHA256
		sport[i], dport[i] = int32(e.SrcPort), int32(e.DstPort) //nolint:gosec // ports are validated to 0..65535
		d, _ := json.Marshal(e.Details)
		if e.Details == nil {
			d = []byte("{}")
		}
		details[i] = string(d)
	}
	accepted := 0
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('netguard.ingest', 0))`); err != nil {
			return fmt.Errorf("ingest lock: %w", err)
		}
		now := s.now()
		if n > 0 {
			tag, err := tx.Exec(ctx, `
				INSERT INTO netguard.events (sensor_id, ts, received_at, kind, iface, src_ip, src_port, dst_ip, dst_port,
				                             proto, community_id, app_proto, details, raw_sha256)
				SELECT $1::text::uuid, u.ts, $2, u.kind, u.iface, NULLIF(u.src, '')::inet, NULLIF(u.sport, 0),
				       NULLIF(u.dst, '')::inet, NULLIF(u.dport, 0), u.proto, u.cid, u.app, u.details::jsonb, decode(u.raw, 'hex')
				FROM unnest($3::timestamptz[], $4::text[], $5::text[], $6::text[], $7::int[], $8::text[], $9::int[],
				            $10::text[], $11::text[], $12::text[], $13::text[], $14::text[])
				     AS u(ts, kind, iface, src, sport, dst, dport, proto, cid, app, details, raw)
				ON CONFLICT (raw_sha256) DO NOTHING`,
				sensor.ID, now, ts, kind, iface, src, sport, dst, dport, proto, cid, app, details, raw)
			if err != nil {
				return fmt.Errorf("insert events: %w", err)
			}
			accepted = int(tag.RowsAffected())
		}
		ifaces := req.Interfaces
		if ifaces == nil {
			ifaces = []string{}
		}
		_, err := tx.Exec(ctx, `UPDATE netguard.sensors SET last_seen_at = $2, engine = $3, interfaces = $4, engine_error = $5,
			events_total = events_total + $6 WHERE id = $1::text::uuid`, sensor.ID, now, req.Engine, ifaces, req.EngineError, accepted)
		return err
	})
	return accepted, err
}

// ActiveScopes returns the signed scopes sensors should run now.
func (s *Postgres) ActiveScopes(ctx context.Context) ([]ngsensor.SignedScope, error) {
	rows, err := s.pool.Query(ctx, `SELECT document, signature FROM netguard.scopes
		WHERE revoked_at IS NULL AND valid_until > $1 ORDER BY issued_at`, s.now())
	if err != nil {
		return nil, fmt.Errorf("active scopes: %w", err)
	}
	defer rows.Close()
	out := []ngsensor.SignedScope{}
	for rows.Next() {
		var ss ngsensor.SignedScope
		if err := rows.Scan(&ss.Document, &ss.Signature); err != nil {
			return nil, err
		}
		out = append(out, ss)
	}
	return out, rows.Err()
}

// --- Events ------------------------------------------------------------------------------

const eventColumns = `e.id, e.sensor_id::text, e.ts, e.kind, e.iface, COALESCE(host(e.src_ip), ''), COALESCE(e.src_port, 0),
	COALESCE(host(e.dst_ip), ''), COALESCE(e.dst_port, 0), e.proto, e.community_id, e.app_proto, e.details, encode(e.raw_sha256, 'hex')`

func scanEvent(row pgx.Row) (domain.Event, error) {
	var e domain.Event
	var details []byte
	err := row.Scan(&e.ID, &e.SensorID, &e.Time, &e.Kind, &e.Interface, &e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort,
		&e.Proto, &e.CommunityID, &e.AppProto, &details, &e.RawSHA256)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Event{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Event{}, fmt.Errorf("scan event: %w", err)
	}
	e.Time = e.Time.UTC()
	e.Details = jsonMap(details)
	return e, nil
}

func collectEvents(rows pgx.Rows, err error) ([]domain.Event, error) {
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()
	out := []domain.Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListEvents returns events, newest first.
func (s *Postgres) ListEvents(ctx context.Context, f domain.EventFilter) ([]domain.Event, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	var ip any
	if f.IP != "" {
		ip = f.IP
	}
	var since any
	if !f.Since.IsZero() {
		since = f.Since
	}
	var before any
	if f.Before > 0 {
		before = f.Before
	}
	return collectEvents(s.pool.Query(ctx, `SELECT `+eventColumns+` FROM netguard.events e
		WHERE ($1::inet IS NULL OR e.src_ip = $1::inet OR e.dst_ip = $1::inet)
		  AND ($2::text = '' OR e.kind = $2)
		  AND ($3::timestamptz IS NULL OR e.ts >= $3)
		  AND ($4::bigint IS NULL OR e.id < $4)
		ORDER BY e.id DESC LIMIT $5`, ip, f.Kind, since, before, f.Limit))
}

// GetEvent returns one event.
func (s *Postgres) GetEvent(ctx context.Context, id int64) (domain.Event, error) {
	return scanEvent(s.pool.QueryRow(ctx, `SELECT `+eventColumns+` FROM netguard.events e WHERE e.id = $1`, id))
}

// Overview summarises NetGuard's state.
func (s *Postgres) Overview(ctx context.Context) (domain.Overview, error) {
	now := s.now()
	o := domain.Overview{EventsByKind: map[string]int{}, OpenAlerts: map[string]int{}}
	err := s.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM netguard.sensors),
		(SELECT count(*) FROM netguard.sensors WHERE last_seen_at > $1),
		(SELECT count(*) FROM netguard.events WHERE ts > $2),
		(SELECT count(*) FROM netguard.incidents WHERE status <> 'resolved'),
		(SELECT count(*) FROM netguard.assets),
		(SELECT count(*) FROM netguard.assets a WHERE NOT EXISTS (
			SELECT 1 FROM netguard.attributions t WHERE t.ip = a.ip AND t.valid_to IS NULL)),
		(SELECT count(*) FROM netguard.scopes WHERE revoked_at IS NULL AND valid_until > $3)`,
		now.Add(-domain.SensorSilentAfter), now.Add(-24*time.Hour), now).
		Scan(&o.Sensors, &o.SensorsReporting, &o.Events24h, &o.OpenIncidents, &o.Assets, &o.Unattributed, &o.ActiveScopes)
	if err != nil {
		return o, fmt.Errorf("overview: %w", err)
	}
	if err := countInto(ctx, s.pool, o.EventsByKind, `SELECT kind, count(*) FROM netguard.events WHERE ts > $1 GROUP BY kind`, now.Add(-time.Hour)); err != nil {
		return o, err
	}
	err = countInto(ctx, s.pool, o.OpenAlerts, `SELECT severity, count(*) FROM netguard.alerts WHERE status IN ('open', 'acknowledged') GROUP BY severity`)
	return o, err
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func countInto(ctx context.Context, q querier, into map[string]int, sql string, args ...any) error {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("count: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return err
		}
		into[k] = n
	}
	return rows.Err()
}

// PruneEvents deletes telemetry older than before that detection has
// processed, in chunks.
func (s *Postgres) PruneEvents(ctx context.Context, before time.Time) (int64, error) {
	var total int64
	for {
		tag, err := s.pool.Exec(ctx, `DELETE FROM netguard.events WHERE id IN (
			SELECT id FROM netguard.events WHERE ts < $1
			  AND id <= (SELECT position FROM netguard.cursors WHERE name = 'detect') LIMIT 5000)`, before)
		if err != nil {
			return total, fmt.Errorf("prune events: %w", err)
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < 5000 {
			return total, nil
		}
	}
}
