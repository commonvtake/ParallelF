// Package store persists ParallelF Cloud state in PostgreSQL using pgx.
//
// Every change commits in one transaction together with the workload's
// history entry, its audit entry and its outbox event, so none of them can
// exist without the others.
package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/commonvtake/parallelf/services/cloud/internal/audit"
	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
)

// PostgreSQL error codes.
const (
	uniqueViolation    = "23505"
	exclusionViolation = "23P01"
)

// Encoder turns domain changes into versioned outbox events
// (implemented by the events package).
type Encoder interface {
	NodeRegistered(n domain.Node) (domain.OutboxEvent, error)
	NodeStatusChanged(n domain.Node, from, to string, at time.Time) (domain.OutboxEvent, error)
	NetworkCreated(n domain.Network) (domain.OutboxEvent, error)
	NetworkDeleted(n domain.Network, by string, at time.Time) (domain.OutboxEvent, error)
	WorkloadCreated(w domain.Workload) (domain.OutboxEvent, error)
	WorkloadStateChanged(w domain.Workload, from string, at time.Time) (domain.OutboxEvent, error)
	WorkloadDeleted(w domain.Workload, at time.Time) (domain.OutboxEvent, error)
}

// Options configures a Postgres store.
type Options struct {
	Encoder      Encoder
	NewID        func() string
	Now          func() time.Time
	Overcommit   domain.Overcommit
	DefaultQuota domain.Quota
}

// Postgres is the cloud store.
type Postgres struct {
	pool *pgxpool.Pool
	opts Options
}

// Open creates a connection pool. Connections are established lazily; use
// Ping to check that the database is reachable.
func Open(ctx context.Context, databaseURL string, opts Options) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		// The parse error can echo the URL, which contains the password.
		return nil, errors.New("PF_DATABASE_URL is not a valid PostgreSQL connection string")
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Postgres{pool: pool, opts: opts}, nil
}

// Close releases every pooled connection.
func (s *Postgres) Close() { s.pool.Close() }

// Ping reports whether the database answers. It is the readiness check.
func (s *Postgres) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// now returns the current time at the precision PostgreSQL stores.
func (s *Postgres) now() time.Time { return audit.Truncate(s.opts.Now()) }

func (s *Postgres) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
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

func pgCode(err error) (code, constraint string) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code, pgErr.ConstraintName
	}
	return "", ""
}

func insertOutbox(ctx context.Context, tx pgx.Tx, evt domain.OutboxEvent) error {
	headers, err := json.Marshal(evt.Headers)
	if err != nil {
		return fmt.Errorf("encode event headers: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO cloud.outbox (id, subject, event_type, payload, headers)
		VALUES ($1::text::uuid, $2, $3, $4, $5)`,
		evt.ID, evt.Subject, evt.Type, evt.Payload, headers)
	if err != nil {
		return fmt.Errorf("insert outbox event: %w", err)
	}
	return nil
}

// encoded is an Encoder result; ev wraps one so it can be passed to emit
// in a single argument: emit(ctx, tx, ev(enc.NetworkCreated(n))).
type encoded struct {
	evt domain.OutboxEvent
	err error
}

func ev(evt domain.OutboxEvent, err error) encoded { return encoded{evt, err} }

// emit writes an encoded event to the outbox.
func emit(ctx context.Context, tx pgx.Tx, e encoded) error {
	if e.err != nil {
		return fmt.Errorf("encode event: %w", e.err)
	}
	return insertOutbox(ctx, tx, e.evt)
}

// auditRecord is one audit entry to append.
type auditRecord struct {
	Actor        domain.Actor
	Action       string
	ResourceType string
	ResourceID   string
	ProjectID    string
	Outcome      string
	Details      map[string]string
}

// appendAudit adds an entry to the hash chain. A transaction-scoped
// advisory lock serialises writers, so each entry chains onto the one
// committed before it.
func (s *Postgres) appendAudit(ctx context.Context, tx pgx.Tx, r auditRecord) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('cloud.audit_log', 0))`); err != nil {
		return fmt.Errorf("lock audit chain: %w", err)
	}
	var prev []byte
	err := tx.QueryRow(ctx, `SELECT hash FROM cloud.audit_log ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		prev = audit.Genesis
	case err != nil:
		return fmt.Errorf("read audit chain head: %w", err)
	}
	if r.Outcome == "" {
		r.Outcome = "success"
	}
	if r.Details == nil {
		r.Details = map[string]string{}
	}
	entry := audit.Entry{
		ID: s.opts.NewID(), At: s.now(),
		ActorType: r.Actor.Type, ActorID: r.Actor.ID, ActorName: r.Actor.Name,
		Action: r.Action, ResourceType: r.ResourceType, ResourceID: r.ResourceID, ProjectID: r.ProjectID,
		Outcome: r.Outcome, RequestID: r.Actor.RequestID, Details: r.Details,
	}
	hash := audit.Hash(prev, entry)
	details, err := json.Marshal(entry.Details)
	if err != nil {
		return fmt.Errorf("encode audit details: %w", err)
	}
	var project any
	if entry.ProjectID != "" {
		project = entry.ProjectID
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO cloud.audit_log (id, ts, actor_type, actor_id, actor_name, action, resource_type,
		                             resource_id, project_id, outcome, request_id, details, prev_hash, hash)
		VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9::text::uuid, $10, $11, $12, $13, $14)`,
		entry.ID, entry.At, entry.ActorType, entry.ActorID, entry.ActorName, entry.Action, entry.ResourceType,
		entry.ResourceID, project, entry.Outcome, entry.RequestID, details, prev, hash)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

// ListAudit returns audit entries, newest first.
func (s *Postgres) ListAudit(ctx context.Context, f domain.AuditFilter) ([]domain.AuditEntry, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT seq, id::text, ts, actor_type, actor_id, actor_name, action, resource_type, resource_id,
		       COALESCE(project_id::text, ''), outcome, request_id, details, prev_hash, hash
		FROM cloud.audit_log
		WHERE ($1 = '' OR resource_type = $1)
		  AND ($2 = '' OR resource_id = $2)
		  AND ($3 = 0 OR seq < $3)
		ORDER BY seq DESC
		LIMIT $4`, f.ResourceType, f.ResourceID, f.BeforeSeq, f.Limit)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var out []domain.AuditEntry
	for rows.Next() {
		e, _, _, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func scanAudit(row pgx.Row) (domain.AuditEntry, []byte, []byte, error) {
	var (
		e             domain.AuditEntry
		details       []byte
		prevHash, sum []byte
	)
	err := row.Scan(&e.Seq, &e.ID, &e.At, &e.ActorType, &e.ActorID, &e.ActorName, &e.Action, &e.ResourceType,
		&e.ResourceID, &e.ProjectID, &e.Outcome, &e.RequestID, &details, &prevHash, &sum)
	if err != nil {
		return domain.AuditEntry{}, nil, nil, fmt.Errorf("scan audit entry: %w", err)
	}
	e.At = e.At.UTC()
	e.Details = map[string]string{}
	if err := json.Unmarshal(details, &e.Details); err != nil {
		return domain.AuditEntry{}, nil, nil, fmt.Errorf("decode audit details: %w", err)
	}
	e.PrevHash = hex.EncodeToString(prevHash)
	e.Hash = hex.EncodeToString(sum)
	return e, prevHash, sum, nil
}

// VerifyAudit recomputes the whole hash chain.
func (s *Postgres) VerifyAudit(ctx context.Context) (domain.AuditVerification, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT seq, id::text, ts, actor_type, actor_id, actor_name, action, resource_type, resource_id,
		       COALESCE(project_id::text, ''), outcome, request_id, details, prev_hash, hash
		FROM cloud.audit_log ORDER BY seq`)
	if err != nil {
		return domain.AuditVerification{}, fmt.Errorf("read audit chain: %w", err)
	}
	defer rows.Close()
	v := audit.NewVerifier()
	for rows.Next() {
		e, prev, sum, err := scanAudit(rows)
		if err != nil {
			return domain.AuditVerification{}, err
		}
		v.Next(e.Seq, audit.Entry{
			ID: e.ID, At: e.At, ActorType: e.ActorType, ActorID: e.ActorID, ActorName: e.ActorName,
			Action: e.Action, ResourceType: e.ResourceType, ResourceID: e.ResourceID, ProjectID: e.ProjectID,
			Outcome: e.Outcome, RequestID: e.RequestID, Details: e.Details,
		}, prev, sum)
	}
	if err := rows.Err(); err != nil {
		return domain.AuditVerification{}, err
	}
	entries, bad := v.Result()
	return domain.AuditVerification{Valid: bad == 0, Entries: entries, FirstInvalidSeq: bad, CheckedAt: s.opts.Now().UTC()}, nil
}
