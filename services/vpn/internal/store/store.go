// Package store keeps pf-vpnd's state in PostgreSQL (schema vpn).
//
// Every change that alters what a gateway must configure increments the
// desired-state revision in the same transaction and wakes long-polling
// agents after commit.
package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/commonvtake/parallelf/pkg/auditlog/pgaudit"
	"github.com/commonvtake/parallelf/pkg/outbox"
	"github.com/commonvtake/parallelf/pkg/vpnagent"
	"github.com/commonvtake/parallelf/services/vpn/internal/domain"
)

// Encoder turns domain changes into outbox events.
type Encoder interface {
	GatewayRegistered(g domain.Gateway) (outbox.Event, error)
	GatewayStatusChanged(g domain.Gateway, from string, at time.Time) (outbox.Event, error)
	DeviceCreated(d domain.Device) (outbox.Event, error)
	DeviceStateChanged(d domain.Device, from, actor string, at time.Time) (outbox.Event, error)
	DeviceActivated(d domain.Device, actor string, at time.Time) (outbox.Event, error)
	DeviceDeactivated(d domain.Device, actor string, at time.Time) (outbox.Event, error)
	PeerConnectionChanged(d domain.Device, at time.Time) (outbox.Event, error)
	PolicyChanged(p domain.Policy, change, actor string, at time.Time) (outbox.Event, error)
}

// PSKBox encrypts pre-shared keys; nil when they are not configured.
type PSKBox interface {
	Generate(associated string) (string, []byte, error)
	Open(ciphertext []byte, associated string) (string, error)
}

// Options configure the store.
type Options struct {
	Encoder   Encoder
	PSK       PSKBox
	NewID     func() string
	Now       func() time.Time
	Tunnel    netip.Prefix
	DeviceTTL time.Duration
}

// Postgres is the store.
type Postgres struct {
	pool  *pgxpool.Pool
	opts  Options
	audit *pgaudit.Log

	mu      sync.Mutex
	changed chan struct{}
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
	return &Postgres{pool: pool, opts: opts, audit: pgaudit.New("vpn", opts.NewID, opts.Now), changed: make(chan struct{})}, nil
}

// Close releases the pool.
func (s *Postgres) Close() { s.pool.Close() }

// Ping checks the connection.
func (s *Postgres) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

func (s *Postgres) now() time.Time { return s.opts.Now().UTC().Truncate(time.Microsecond) }

// Changed returns a channel closed at the next desired-state change.
func (s *Postgres) Changed() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changed
}

func (s *Postgres) notify() {
	s.mu.Lock()
	close(s.changed)
	s.changed = make(chan struct{})
	s.mu.Unlock()
}

// inTx runs fn in a transaction. bump reports whether fn changed desired
// state; waiters are woken after a successful commit.
func (s *Postgres) inTx(ctx context.Context, fn func(tx pgx.Tx) (bump bool, err error)) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	bump, err := fn(tx)
	if err != nil {
		return err
	}
	if bump {
		if _, err := tx.Exec(ctx, `UPDATE vpn.state SET revision = revision + 1`); err != nil {
			return fmt.Errorf("bump revision: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	if bump {
		s.notify()
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
	return outbox.Insert(ctx, tx, "vpn", evt)
}

func (s *Postgres) appendAudit(ctx context.Context, tx pgx.Tx, actor domain.Actor, action, resourceType, resourceID string, details map[string]string) error {
	return s.audit.Append(ctx, tx, pgaudit.Record{
		Actor:  pgaudit.Actor{Type: actor.Type, ID: actor.ID, Name: actor.Name, RequestID: actor.RequestID},
		Action: action, ResourceType: resourceType, ResourceID: resourceID, Details: details,
	})
}

// Revision returns the current desired-state revision.
func (s *Postgres) Revision(ctx context.Context) (int64, error) {
	var r int64
	err := s.pool.QueryRow(ctx, `SELECT revision FROM vpn.state`).Scan(&r)
	return r, err
}

// --- Audit ------------------------------------------------------------------------

// ListAudit returns audit entries, newest first.
func (s *Postgres) ListAudit(ctx context.Context, f pgaudit.Filter) ([]pgaudit.Entry, error) {
	return s.audit.List(ctx, s.pool, f)
}

// VerifyAudit recomputes the hash chain.
func (s *Postgres) VerifyAudit(ctx context.Context) (pgaudit.Verification, error) {
	return s.audit.Verify(ctx, s.pool)
}

// --- Gateways -----------------------------------------------------------------------

const gatewayColumns = `g.id::text, g.name, g.status, g.public_key, g.endpoint, g.listen_port, g.agent_version,
	g.applied_revision, g.apply_error, g.registered_at, g.last_seen_at`

func (s *Postgres) scanGateway(row pgx.Row) (domain.Gateway, error) {
	var g domain.Gateway
	err := row.Scan(&g.ID, &g.Name, &g.Status, &g.PublicKey, &g.Endpoint, &g.ListenPort, &g.AgentVersion,
		&g.AppliedRevision, &g.ApplyError, &g.RegisteredAt, &g.LastSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Gateway{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Gateway{}, fmt.Errorf("scan gateway: %w", err)
	}
	g.RegisteredAt, g.LastSeenAt = g.RegisteredAt.UTC(), g.LastSeenAt.UTC()
	g.Address = netip.PrefixFrom(domain.GatewayAddress(s.opts.Tunnel), s.opts.Tunnel.Bits()).String()
	return g, nil
}

// RegisterGateway adds a gateway or, for a known name, replaces its
// credential and key (a reinstalled host).
func (s *Postgres) RegisterGateway(ctx context.Context, r domain.GatewayRegistration) (domain.Gateway, error) {
	var g domain.Gateway
	err := s.inTx(ctx, func(tx pgx.Tx) (bool, error) {
		now := s.now()
		var err error
		g, err = s.scanGateway(tx.QueryRow(ctx, `
			INSERT INTO vpn.gateways AS g (id, name, token_hash, public_key, endpoint, listen_port, agent_version, registered_at, last_seen_at)
			VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $8)
			ON CONFLICT (name) DO UPDATE SET token_hash = EXCLUDED.token_hash, public_key = EXCLUDED.public_key,
				endpoint = EXCLUDED.endpoint, listen_port = EXCLUDED.listen_port, agent_version = EXCLUDED.agent_version,
				status = 'READY', applied_revision = 0, last_seen_at = EXCLUDED.last_seen_at
			RETURNING `+gatewayColumns, s.opts.NewID(), r.Name, r.TokenHash, r.PublicKey, r.Endpoint, r.ListenPort, r.AgentVersion, now))
		if err != nil {
			return false, fmt.Errorf("register gateway: %w", err)
		}
		evt, eerr := s.opts.Encoder.GatewayRegistered(g)
		if err := s.emit(ctx, tx, evt, eerr); err != nil {
			return false, err
		}
		actor := domain.Actor{Type: "agent", ID: g.ID, Name: g.Name}
		return true, s.appendAudit(ctx, tx, actor, "vpn.gateways.register", "gateway", g.ID,
			map[string]string{"public_key": g.PublicKey, "endpoint": g.Endpoint})
	})
	return g, err
}

// AuthenticateGateway finds the gateway holding a credential.
func (s *Postgres) AuthenticateGateway(ctx context.Context, tokenHash []byte) (domain.Gateway, error) {
	g, err := s.scanGateway(s.pool.QueryRow(ctx, `SELECT `+gatewayColumns+` FROM vpn.gateways g WHERE g.token_hash = $1`, tokenHash))
	if errors.Is(err, domain.ErrNotFound) {
		return domain.Gateway{}, domain.ErrUnauthorizedGW
	}
	return g, err
}

// ListGateways returns every gateway.
func (s *Postgres) ListGateways(ctx context.Context) ([]domain.Gateway, error) {
	rev, err := s.Revision(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+gatewayColumns+` FROM vpn.gateways g ORDER BY g.name`)
	if err != nil {
		return nil, fmt.Errorf("list gateways: %w", err)
	}
	defer rows.Close()
	out := []domain.Gateway{}
	for rows.Next() {
		g, err := s.scanGateway(rows)
		if err != nil {
			return nil, err
		}
		g.Revision = rev
		out = append(out, g)
	}
	return out, rows.Err()
}

// primaryGateway returns the gateway devices connect to: the ready one
// that registered first (Phase 3 runs one gateway).
func (s *Postgres) primaryGateway(ctx context.Context, q pgx.Tx) (domain.Gateway, error) {
	g, err := s.scanGateway(q.QueryRow(ctx, `SELECT `+gatewayColumns+` FROM vpn.gateways g
		ORDER BY (g.status = 'READY') DESC, g.registered_at LIMIT 1`))
	if errors.Is(err, domain.ErrNotFound) {
		return domain.Gateway{}, domain.ErrNoGateway
	}
	return g, err
}

// DeleteGateway removes a gateway that stopped reporting.
func (s *Postgres) DeleteGateway(ctx context.Context, id string, actor domain.Actor) error {
	return s.inTx(ctx, func(tx pgx.Tx) (bool, error) {
		var name, status string
		err := tx.QueryRow(ctx, `SELECT name, status FROM vpn.gateways WHERE id = $1::text::uuid FOR UPDATE`, id).Scan(&name, &status)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, domain.ErrNotFound
		}
		if err != nil {
			return false, err
		}
		if status == domain.GatewayReady {
			return false, domain.ErrGatewayActive
		}
		if _, err := tx.Exec(ctx, `DELETE FROM vpn.gateways WHERE id = $1::text::uuid`, id); err != nil {
			return false, fmt.Errorf("delete gateway: %w", err)
		}
		return false, s.appendAudit(ctx, tx, actor, "vpn.gateways.delete", "gateway", id, map[string]string{"name": name})
	})
}

// MarkSilentGateways sets gateways not heard from since deadline to NOT_READY.
func (s *Postgres) MarkSilentGateways(ctx context.Context, deadline time.Time) ([]domain.Gateway, error) {
	var changed []domain.Gateway
	err := s.inTx(ctx, func(tx pgx.Tx) (bool, error) {
		rows, err := tx.Query(ctx, `SELECT `+gatewayColumns+` FROM vpn.gateways g
			WHERE g.status = 'READY' AND g.last_seen_at < $1 ORDER BY g.id FOR UPDATE`, deadline)
		if err != nil {
			return false, fmt.Errorf("find silent gateways: %w", err)
		}
		for rows.Next() {
			g, err := s.scanGateway(rows)
			if err != nil {
				rows.Close()
				return false, err
			}
			changed = append(changed, g)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return false, err
		}
		now := s.now()
		for i, g := range changed {
			if _, err := tx.Exec(ctx, `UPDATE vpn.gateways SET status = 'NOT_READY' WHERE id = $1::text::uuid`, g.ID); err != nil {
				return false, err
			}
			changed[i].Status = domain.GatewayNotReady
			evt, eerr := s.opts.Encoder.GatewayStatusChanged(changed[i], domain.GatewayReady, now)
			if err := s.emit(ctx, tx, evt, eerr); err != nil {
				return false, err
			}
		}
		return false, nil
	})
	return changed, err
}

// --- Devices ---------------------------------------------------------------------------

const deviceColumns = `d.id::text, d.name, d.owner_subject, d.owner_name, d.public_key, host(d.address), d.groups,
	d.psk_ciphertext, d.state, d.active_until, d.expires_at, d.created_at, d.ended_at, d.last_handshake_at,
	d.endpoint, d.rx_bytes, d.tx_bytes, d.connected`

func (s *Postgres) scanDevice(row pgx.Row) (domain.Device, error) {
	var (
		d         domain.Device
		psk       []byte
		connected bool
	)
	err := row.Scan(&d.ID, &d.Name, &d.OwnerSubject, &d.OwnerName, &d.PublicKey, &d.Address, &d.Groups,
		&psk, &d.State, &d.ActiveUntil, &d.ExpiresAt, &d.CreatedAt, &d.EndedAt, &d.LastHandshakeAt,
		&d.Endpoint, &d.RxBytes, &d.TxBytes, &connected)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Device{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Device{}, fmt.Errorf("scan device: %w", err)
	}
	if d.Groups == nil {
		d.Groups = []string{}
	}
	d.ExpiresAt, d.CreatedAt = d.ExpiresAt.UTC(), d.CreatedAt.UTC()
	return d.WithPSKCiphertext(psk).WithConnected(connected).Derive(s.opts.Now()), nil
}

func (s *Postgres) lockDevice(ctx context.Context, tx pgx.Tx, id string) (domain.Device, error) {
	return s.scanDevice(tx.QueryRow(ctx, `SELECT `+deviceColumns+` FROM vpn.devices d WHERE d.id = $1::text::uuid FOR UPDATE`, id))
}

// GetDevice returns a device.
func (s *Postgres) GetDevice(ctx context.Context, id string) (domain.Device, error) {
	return s.scanDevice(s.pool.QueryRow(ctx, `SELECT `+deviceColumns+` FROM vpn.devices d WHERE d.id = $1::text::uuid`, id))
}

// ListDevices returns devices, newest first: one owner's, or everyone's
// when owner is empty. Ended devices are included only when ended is set.
func (s *Postgres) ListDevices(ctx context.Context, owner string, ended bool) ([]domain.Device, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+deviceColumns+` FROM vpn.devices d
		WHERE ($1 = '' OR d.owner_subject = $1) AND ($2 OR d.state IN ('PENDING', 'ENROLLED'))
		ORDER BY d.created_at DESC, d.id LIMIT 500`, owner, ended)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()
	out := []domain.Device{}
	for rows.Next() {
		d, err := s.scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// CreateDevice enrols a device: allocates its tunnel address and, when
// asked, a pre-shared key, which is returned in clear text this once.
func (s *Postgres) CreateDevice(ctx context.Context, in domain.DeviceInput, owner domain.Owner, actor domain.Actor) (domain.Device, string, error) {
	if in.PresharedKey && s.opts.PSK == nil {
		return domain.Device{}, "", domain.ErrPSKUnavailable
	}
	var (
		created domain.Device
		psk     string
	)
	err := s.inTx(ctx, func(tx pgx.Tx) (bool, error) {
		gw, err := s.primaryGateway(ctx, tx)
		if err != nil {
			return false, err
		}
		if gw.PublicKey == in.PublicKey {
			return false, domain.ErrKeyTaken
		}
		// Serialise address allocation.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('vpn.addresses', 0))`); err != nil {
			return false, fmt.Errorf("lock address pool: %w", err)
		}
		rows, err := tx.Query(ctx, `SELECT host(address) FROM vpn.devices WHERE state IN ('PENDING', 'ENROLLED')`)
		if err != nil {
			return false, fmt.Errorf("read used addresses: %w", err)
		}
		used := map[netip.Addr]bool{}
		for rows.Next() {
			var a string
			if err := rows.Scan(&a); err != nil {
				rows.Close()
				return false, err
			}
			if ip, err := netip.ParseAddr(a); err == nil {
				used[ip] = true
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return false, err
		}
		address, err := domain.NextAddress(s.opts.Tunnel, used)
		if err != nil {
			return false, err
		}

		id, now := s.opts.NewID(), s.now()
		var ciphertext []byte
		if in.PresharedKey {
			if psk, ciphertext, err = s.opts.PSK.Generate(id); err != nil {
				return false, fmt.Errorf("generate pre-shared key: %w", err)
			}
		}
		groups := owner.Groups
		if groups == nil {
			groups = []string{}
		}
		created, err = s.scanDevice(tx.QueryRow(ctx, `
			INSERT INTO vpn.devices AS d (id, owner_subject, owner_name, name, public_key, address, groups, psk_ciphertext, expires_at, created_at)
			VALUES ($1::text::uuid, $2, $3, $4, $5, $6::inet, $7, $8, $9, $10)
			RETURNING `+deviceColumns,
			id, owner.Subject, owner.Name, in.Name, in.PublicKey, address.String()+"/32", groups, ciphertext,
			now.Add(s.opts.DeviceTTL), now))
		if err != nil {
			switch code, constraint := pgCode(err); {
			case code == "23505" && constraint == "devices_live_key":
				return false, domain.ErrKeyTaken
			case code == "23505" && constraint == "devices_live_name":
				return false, domain.ErrNameTaken
			}
			return false, fmt.Errorf("insert device: %w", err)
		}
		evt, eerr := s.opts.Encoder.DeviceCreated(created)
		if err := s.emit(ctx, tx, evt, eerr); err != nil {
			return false, err
		}
		return true, s.appendAudit(ctx, tx, actor, "vpn.devices.create", "device", id, map[string]string{
			"name": in.Name, "owner": owner.Subject, "address": created.Address, "public_key": in.PublicKey,
			"preshared_key": fmt.Sprint(in.PresharedKey),
		})
	})
	return created, psk, err
}

// Activate lets a device send traffic until until.
func (s *Postgres) Activate(ctx context.Context, id string, until time.Time, actor domain.Actor) (domain.Device, error) {
	var d domain.Device
	err := s.inTx(ctx, func(tx pgx.Tx) (bool, error) {
		var err error
		if d, err = s.lockDevice(ctx, tx, id); err != nil {
			return false, err
		}
		if !d.Live() {
			return false, domain.ErrInvalidState
		}
		now := s.now()
		if d.ExpiresAt.Before(until) {
			until = d.ExpiresAt // never beyond the device's own expiry
		}
		if _, err := tx.Exec(ctx, `UPDATE vpn.activations SET ended_at = $2, ended_by = 'superseded'
			WHERE device_id = $1::text::uuid AND ended_at IS NULL`, id, now); err != nil {
			return false, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO vpn.activations (device_id, subject, started_at, until) VALUES ($1::text::uuid, $2, $3, $4)`,
			id, actor.ID, now, until); err != nil {
			return false, fmt.Errorf("record activation: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE vpn.devices SET active_until = $2 WHERE id = $1::text::uuid`, id, until); err != nil {
			return false, err
		}
		d.ActiveUntil = &until
		d = d.Derive(s.opts.Now())
		evt, eerr := s.opts.Encoder.DeviceActivated(d, actor.ID, now)
		if err := s.emit(ctx, tx, evt, eerr); err != nil {
			return false, err
		}
		return true, s.appendAudit(ctx, tx, actor, "vpn.devices.activate", "device", id,
			map[string]string{"until": until.Format(time.RFC3339), "address": d.Address})
	})
	return d, err
}

// Deactivate ends a device's activation now.
func (s *Postgres) Deactivate(ctx context.Context, id string, actor domain.Actor) (domain.Device, error) {
	var d domain.Device
	err := s.inTx(ctx, func(tx pgx.Tx) (bool, error) {
		var err error
		if d, err = s.lockDevice(ctx, tx, id); err != nil {
			return false, err
		}
		if !d.Active {
			return false, domain.ErrInvalidState
		}
		now := s.now()
		if err := s.endActivation(ctx, tx, id, now, "deactivated"); err != nil {
			return false, err
		}
		d.ActiveUntil = nil
		d = d.Derive(s.opts.Now())
		evt, eerr := s.opts.Encoder.DeviceDeactivated(d, actor.ID, now)
		if err := s.emit(ctx, tx, evt, eerr); err != nil {
			return false, err
		}
		return true, s.appendAudit(ctx, tx, actor, "vpn.devices.deactivate", "device", id, map[string]string{"address": d.Address})
	})
	return d, err
}

func (s *Postgres) endActivation(ctx context.Context, tx pgx.Tx, id string, now time.Time, reason string) error {
	if _, err := tx.Exec(ctx, `UPDATE vpn.activations SET ended_at = $2, ended_by = $3
		WHERE device_id = $1::text::uuid AND ended_at IS NULL`, id, now, reason); err != nil {
		return fmt.Errorf("end activation: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE vpn.devices SET active_until = NULL WHERE id = $1::text::uuid`, id); err != nil {
		return fmt.Errorf("clear activation: %w", err)
	}
	return nil
}

// Revoke ends a device for good: its key and address are released and the
// gateway removes the peer and its connections.
func (s *Postgres) Revoke(ctx context.Context, id string, actor domain.Actor) (domain.Device, error) {
	return s.end(ctx, id, domain.StateRevoked, actor, "vpn.devices.revoke")
}

func (s *Postgres) end(ctx context.Context, id, state string, actor domain.Actor, action string) (domain.Device, error) {
	var d domain.Device
	err := s.inTx(ctx, func(tx pgx.Tx) (bool, error) {
		var err error
		if d, err = s.lockDevice(ctx, tx, id); err != nil {
			return false, err
		}
		if !d.Live() {
			return false, domain.ErrInvalidState
		}
		now := s.now()
		if err := s.endActivation(ctx, tx, id, now, state); err != nil {
			return false, err
		}
		if _, err := tx.Exec(ctx, `UPDATE vpn.devices SET state = $2, ended_at = $3, connected = false WHERE id = $1::text::uuid`,
			id, state, now); err != nil {
			return false, fmt.Errorf("end device: %w", err)
		}
		from := d.State
		d.State, d.EndedAt, d.ActiveUntil = state, &now, nil
		d = d.Derive(s.opts.Now())
		evt, eerr := s.opts.Encoder.DeviceStateChanged(d, from, actor.ID, now)
		if err := s.emit(ctx, tx, evt, eerr); err != nil {
			return false, err
		}
		return true, s.appendAudit(ctx, tx, actor, action, "device", id,
			map[string]string{"address": d.Address, "public_key": d.PublicKey, "owner": d.OwnerSubject})
	})
	return d, err
}

// SetGroups replaces a device's groups.
func (s *Postgres) SetGroups(ctx context.Context, id string, groups []string, actor domain.Actor) (domain.Device, error) {
	var d domain.Device
	err := s.inTx(ctx, func(tx pgx.Tx) (bool, error) {
		var err error
		if d, err = s.lockDevice(ctx, tx, id); err != nil {
			return false, err
		}
		if !d.Live() {
			return false, domain.ErrInvalidState
		}
		if _, err := tx.Exec(ctx, `UPDATE vpn.devices SET groups = $2 WHERE id = $1::text::uuid`, id, groups); err != nil {
			return false, err
		}
		before := fmt.Sprint(d.Groups)
		d.Groups = groups
		return true, s.appendAudit(ctx, tx, actor, "vpn.devices.groups", "device", id,
			map[string]string{"before": before, "after": fmt.Sprint(groups)})
	})
	return d, err
}

// ExpireDevices ends devices past their expiry.
func (s *Postgres) ExpireDevices(ctx context.Context, now time.Time) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text FROM vpn.devices WHERE state IN ('PENDING', 'ENROLLED') AND expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if _, err := s.end(ctx, id, domain.StateExpired, domain.Actor{Type: "system", ID: "pf-vpnd", Name: "expiry"}, "vpn.devices.expire"); err == nil {
			n++
		} else if !errors.Is(err, domain.ErrInvalidState) {
			return n, err
		}
	}
	return n, nil
}

// DeviceConfig returns what a device needs to connect (without keys).
func (s *Postgres) DeviceConfig(ctx context.Context, d domain.Device) (domain.ClientConfig, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return domain.ClientConfig{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	gw, err := s.primaryGateway(ctx, tx)
	if err != nil {
		return domain.ClientConfig{}, err
	}
	policies, err := s.listPolicies(ctx, tx)
	if err != nil {
		return domain.ClientConfig{}, err
	}
	return domain.ClientConfig{
		Address:             d.Address + "/32",
		GatewayPublicKey:    gw.PublicKey,
		Endpoint:            gw.Endpoint,
		AllowedIPs:          domain.ClientAllowedIPs(s.opts.Tunnel, d.Groups, policies),
		PersistentKeepalive: 25,
	}, nil
}

// DeviceMetrics returns traffic per sample since since, oldest first.
func (s *Postgres) DeviceMetrics(ctx context.Context, id string, since time.Time) ([]domain.MetricPoint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ts, rx_bytes - lag(rx_bytes, 1, rx_bytes) OVER w, tx_bytes - lag(tx_bytes, 1, tx_bytes) OVER w
		FROM vpn.peer_stats WHERE device_id = $1::text::uuid AND ts >= $2
		WINDOW w AS (ORDER BY ts) ORDER BY ts`, id, since)
	if err != nil {
		return nil, fmt.Errorf("device metrics: %w", err)
	}
	defer rows.Close()
	out := []domain.MetricPoint{}
	for rows.Next() {
		var p domain.MetricPoint
		if err := rows.Scan(&p.At, &p.RxBytes, &p.TxBytes); err != nil {
			return nil, err
		}
		p.At = p.At.UTC()
		// Counters restart when a peer is re-added; never report negatives.
		p.RxBytes, p.TxBytes = max(p.RxBytes, 0), max(p.TxBytes, 0)
		out = append(out, p)
	}
	return out, rows.Err()
}

// PruneStats deletes samples older than before.
func (s *Postgres) PruneStats(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM vpn.peer_stats WHERE ts < $1`, before)
	return tag.RowsAffected(), err
}

// --- Policies ------------------------------------------------------------------------------

const policyColumns = `p.id::text, p.name, p.priority, p.action, p.groups, p.destinations, p.protocol, p.ports,
	p.description, p.created_by, p.created_at`

func scanPolicy(row pgx.Row) (domain.Policy, error) {
	var p domain.Policy
	err := row.Scan(&p.ID, &p.Name, &p.Priority, &p.Action, &p.Groups, &p.Destinations, &p.Protocol, &p.Ports,
		&p.Description, &p.CreatedBy, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Policy{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Policy{}, fmt.Errorf("scan policy: %w", err)
	}
	if p.Ports == nil {
		p.Ports = []string{}
	}
	p.CreatedAt = p.CreatedAt.UTC()
	return p, nil
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (s *Postgres) listPolicies(ctx context.Context, q querier) ([]domain.Policy, error) {
	rows, err := q.Query(ctx, `SELECT `+policyColumns+` FROM vpn.policies p ORDER BY p.priority, p.name`)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()
	out := []domain.Policy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListPolicies returns every policy in evaluation order.
func (s *Postgres) ListPolicies(ctx context.Context) ([]domain.Policy, error) {
	return s.listPolicies(ctx, s.pool)
}

// CreatePolicy adds a policy (already validated).
func (s *Postgres) CreatePolicy(ctx context.Context, in domain.PolicyInput, actor domain.Actor) (domain.Policy, error) {
	var p domain.Policy
	err := s.inTx(ctx, func(tx pgx.Tx) (bool, error) {
		var err error
		p, err = scanPolicy(tx.QueryRow(ctx, `
			INSERT INTO vpn.policies AS p (id, name, priority, action, groups, destinations, protocol, ports, description, created_by, created_at)
			VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING `+policyColumns,
			s.opts.NewID(), in.Name, in.Priority, in.Action, in.Groups, in.Destinations, in.Protocol, in.Ports,
			in.Description, actor.Name, s.now()))
		if err != nil {
			if code, _ := pgCode(err); code == "23505" {
				return false, domain.ErrNameTaken
			}
			return false, fmt.Errorf("insert policy: %w", err)
		}
		evt, eerr := s.opts.Encoder.PolicyChanged(p, "created", actor.ID, p.CreatedAt)
		if err := s.emit(ctx, tx, evt, eerr); err != nil {
			return false, err
		}
		return true, s.appendAudit(ctx, tx, actor, "vpn.policies.create", "policy", p.ID, map[string]string{
			"name": p.Name, "action": p.Action, "groups": fmt.Sprint(p.Groups), "destinations": fmt.Sprint(p.Destinations),
			"protocol": p.Protocol, "ports": fmt.Sprint(p.Ports), "priority": fmt.Sprint(p.Priority),
		})
	})
	return p, err
}

// GetPolicy returns a policy.
func (s *Postgres) GetPolicy(ctx context.Context, id string) (domain.Policy, error) {
	return scanPolicy(s.pool.QueryRow(ctx, `SELECT `+policyColumns+` FROM vpn.policies p WHERE p.id = $1::text::uuid`, id))
}

// DeletePolicy removes a policy.
func (s *Postgres) DeletePolicy(ctx context.Context, id string, actor domain.Actor) error {
	return s.inTx(ctx, func(tx pgx.Tx) (bool, error) {
		p, err := scanPolicy(tx.QueryRow(ctx, `DELETE FROM vpn.policies p WHERE p.id = $1::text::uuid RETURNING `+policyColumns, id))
		if err != nil {
			return false, err
		}
		evt, eerr := s.opts.Encoder.PolicyChanged(p, "deleted", actor.ID, s.now())
		if err := s.emit(ctx, tx, evt, eerr); err != nil {
			return false, err
		}
		return true, s.appendAudit(ctx, tx, actor, "vpn.policies.delete", "policy", id, map[string]string{"name": p.Name})
	})
}

// --- Agent sync ------------------------------------------------------------------------------

// Sync records what a gateway reports: liveness, applied revision, peer
// statistics, enrolment confirmations and connection changes.
func (s *Postgres) Sync(ctx context.Context, gw domain.Gateway, req vpnagent.SyncRequest) error {
	return s.inTx(ctx, func(tx pgx.Tx) (bool, error) {
		now := s.now()
		var previous string
		if err := tx.QueryRow(ctx, `SELECT status FROM vpn.gateways WHERE id = $1::text::uuid FOR UPDATE`, gw.ID).Scan(&previous); err != nil {
			return false, fmt.Errorf("lock gateway: %w", err)
		}
		pub, endpoint := gw.PublicKey, gw.Endpoint
		if domain.ValidKey(req.PublicKey) {
			pub = req.PublicKey
		}
		if req.Endpoint != "" && len(req.Endpoint) <= 255 {
			endpoint = req.Endpoint
		}
		if _, err := tx.Exec(ctx, `UPDATE vpn.gateways SET status = 'READY', last_seen_at = $2, applied_revision = $3,
			apply_error = $4, public_key = $5, endpoint = $6 WHERE id = $1::text::uuid`,
			gw.ID, now, req.Revision, truncate(req.ApplyError, 1000), pub, endpoint); err != nil {
			return false, fmt.Errorf("update gateway: %w", err)
		}
		bump := pub != gw.PublicKey || endpoint != gw.Endpoint
		if previous != domain.GatewayReady {
			gw.Status = domain.GatewayReady
			evt, eerr := s.opts.Encoder.GatewayStatusChanged(gw, previous, now)
			if err := s.emit(ctx, tx, evt, eerr); err != nil {
				return false, err
			}
		}

		reported := map[string]vpnagent.PeerStatus{}
		for _, p := range req.Peers {
			reported[p.PublicKey] = p
		}
		rows, err := tx.Query(ctx, `SELECT `+deviceColumns+` FROM vpn.devices d WHERE d.state IN ('PENDING', 'ENROLLED')
			ORDER BY d.id FOR UPDATE OF d`)
		if err != nil {
			return false, fmt.Errorf("lock devices: %w", err)
		}
		var devices []domain.Device
		for rows.Next() {
			d, err := s.scanDevice(rows)
			if err != nil {
				rows.Close()
				return false, err
			}
			devices = append(devices, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return false, err
		}

		for _, d := range devices {
			p, present := reported[d.PublicKey]
			if !present {
				continue
			}
			if d.State == domain.StatePending {
				if _, err := tx.Exec(ctx, `UPDATE vpn.devices SET state = 'ENROLLED' WHERE id = $1::text::uuid`, d.ID); err != nil {
					return false, err
				}
				d.State = domain.StateEnrolled
				evt, eerr := s.opts.Encoder.DeviceStateChanged(d, domain.StatePending, gw.ID, now)
				if err := s.emit(ctx, tx, evt, eerr); err != nil {
					return false, err
				}
			}
			var handshake *time.Time
			if p.LatestHandshake > 0 {
				h := time.Unix(p.LatestHandshake, 0).UTC()
				handshake = &h
			}
			connected := domain.Connection(handshake, now) == domain.ConnOnline
			if _, err := tx.Exec(ctx, `UPDATE vpn.devices SET last_handshake_at = $2, rx_bytes = $3, tx_bytes = $4,
				endpoint = $5, connected = $6 WHERE id = $1::text::uuid`,
				d.ID, handshake, p.RxBytes, p.TxBytes, truncate(p.Endpoint, 64), connected); err != nil {
				return false, fmt.Errorf("update peer stats: %w", err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO vpn.peer_stats (device_id, ts, rx_bytes, tx_bytes) VALUES ($1::text::uuid, $2, $3, $4)
				ON CONFLICT DO NOTHING`, d.ID, now, p.RxBytes, p.TxBytes); err != nil {
				return false, fmt.Errorf("insert peer stats: %w", err)
			}
			if connected != d.Connected() {
				d.LastHandshakeAt, d.Endpoint = handshake, truncate(p.Endpoint, 64)
				d = d.WithConnected(connected)
				evt, eerr := s.opts.Encoder.PeerConnectionChanged(d, now)
				if err := s.emit(ctx, tx, evt, eerr); err != nil {
					return false, err
				}
			}
		}
		return bump, nil
	})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// DesiredState builds the complete configuration for a gateway.
func (s *Postgres) DesiredState(ctx context.Context, gw domain.Gateway) (vpnagent.SyncResponse, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return vpnagent.SyncResponse{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var revision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM vpn.state`).Scan(&revision); err != nil {
		return vpnagent.SyncResponse{}, err
	}
	rows, err := tx.Query(ctx, `SELECT `+deviceColumns+` FROM vpn.devices d WHERE d.state IN ('PENDING', 'ENROLLED') ORDER BY d.address`)
	if err != nil {
		return vpnagent.SyncResponse{}, fmt.Errorf("desired devices: %w", err)
	}
	var devices []domain.Device
	for rows.Next() {
		d, err := s.scanDevice(rows)
		if err != nil {
			rows.Close()
			return vpnagent.SyncResponse{}, err
		}
		devices = append(devices, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return vpnagent.SyncResponse{}, err
	}
	policies, err := s.listPolicies(ctx, tx)
	if err != nil {
		return vpnagent.SyncResponse{}, err
	}

	gwAddr := domain.GatewayAddress(s.opts.Tunnel)
	compiled, forwarding := domain.CompilePolicies(policies, devices, gwAddr)
	resp := vpnagent.SyncResponse{
		GatewayID: gw.ID,
		Revision:  revision,
		Interface: vpnagent.Interface{
			Address:    netip.PrefixFrom(gwAddr, s.opts.Tunnel.Bits()).String(),
			ListenPort: gw.ListenPort,
			Forwarding: forwarding,
		},
		Peers:    []vpnagent.Peer{},
		Active:   []vpnagent.Activation{},
		Policies: compiled,
	}
	now := s.opts.Now()
	for _, d := range devices {
		peer := vpnagent.Peer{DeviceID: d.ID, PublicKey: d.PublicKey, Address: d.Address}
		if c := d.PSKCiphertext(); len(c) > 0 && s.opts.PSK != nil {
			if peer.PresharedKey, err = s.opts.PSK.Open(c, d.ID); err != nil {
				return vpnagent.SyncResponse{}, err
			}
		}
		resp.Peers = append(resp.Peers, peer)
		if d.ActiveUntil != nil && d.ActiveUntil.After(now) {
			resp.Active = append(resp.Active, vpnagent.Activation{Address: d.Address, ExpiresAt: d.ActiveUntil.UTC()})
		}
	}
	return resp, nil
}
