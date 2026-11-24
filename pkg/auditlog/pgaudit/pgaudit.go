// Package pgaudit stores a service's audit trail in its PostgreSQL schema.
//
// Every service with an audit trail has a table <schema>.audit_log with the
// same columns (see the services' first migrations) and the same
// append-only triggers. This package appends to it, lists it and verifies
// its hash chain (package auditlog).
package pgaudit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/pkg/auditlog"
)

// The API types live in package auditlog, so packages that only pass
// entries around need no database driver.
type (
	Actor        = auditlog.Actor
	Record       = auditlog.Record
	Entry        = auditlog.View
	Filter       = auditlog.Filter
	Verification = auditlog.Verification
)

// Querier is satisfied by a pool and a transaction.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

var schemaPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// Log is the audit trail of one schema.
type Log struct {
	table string
	lock  string
	newID func() string
	now   func() time.Time
}

// New returns the audit log in schema. It panics on a schema name that is
// not a plain identifier: names come from code, never from input.
func New(schema string, newID func() string, now func() time.Time) *Log {
	if !schemaPattern.MatchString(schema) {
		panic("pgaudit: invalid schema name " + schema)
	}
	return &Log{table: schema + ".audit_log", lock: schema + ".audit_log", newID: newID, now: now}
}

// Append adds r to the chain inside tx. A transaction-scoped advisory lock
// serialises writers, so each entry chains onto the one committed before it.
func (l *Log) Append(ctx context.Context, tx pgx.Tx, r Record) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, l.lock); err != nil {
		return fmt.Errorf("lock audit chain: %w", err)
	}
	var prev []byte
	err := tx.QueryRow(ctx, `SELECT hash FROM `+l.table+` ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		prev = auditlog.Genesis
	case err != nil:
		return fmt.Errorf("read audit chain head: %w", err)
	}
	if r.Outcome == "" {
		r.Outcome = "success"
	}
	if r.Details == nil {
		r.Details = map[string]string{}
	}
	e := auditlog.Entry{
		ID: l.newID(), At: auditlog.Truncate(l.now()),
		ActorType: r.Actor.Type, ActorID: r.Actor.ID, ActorName: r.Actor.Name,
		Action: r.Action, ResourceType: r.ResourceType, ResourceID: r.ResourceID, ProjectID: r.ProjectID,
		Outcome: r.Outcome, RequestID: r.Actor.RequestID, Details: r.Details,
	}
	hash := auditlog.Hash(prev, e)
	details, err := json.Marshal(e.Details)
	if err != nil {
		return fmt.Errorf("encode audit details: %w", err)
	}
	var project any
	if e.ProjectID != "" {
		project = e.ProjectID
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO `+l.table+` (id, ts, actor_type, actor_id, actor_name, action, resource_type,
		                     resource_id, project_id, outcome, request_id, details, prev_hash, hash)
		VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7, $8, $9::text::uuid, $10, $11, $12, $13, $14)`,
		e.ID, e.At, e.ActorType, e.ActorID, e.ActorName, e.Action, e.ResourceType,
		e.ResourceID, project, e.Outcome, e.RequestID, details, prev, hash)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

const columns = `seq, id::text, ts, actor_type, actor_id, actor_name, action, resource_type, resource_id,
	COALESCE(project_id::text, ''), outcome, request_id, details, prev_hash, hash`

// List returns entries matching f, newest first.
func (l *Log) List(ctx context.Context, q Querier, f Filter) ([]Entry, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	rows, err := q.Query(ctx, `SELECT `+columns+` FROM `+l.table+`
		WHERE ($1 = '' OR resource_type = $1) AND ($2 = '' OR resource_id = $2) AND ($3 = 0 OR seq < $3)
		ORDER BY seq DESC LIMIT $4`, f.ResourceType, f.ResourceID, f.BeforeSeq, f.Limit)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		e, _, _, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Verify recomputes the whole chain.
func (l *Log) Verify(ctx context.Context, q Querier) (Verification, error) {
	rows, err := q.Query(ctx, `SELECT `+columns+` FROM `+l.table+` ORDER BY seq`)
	if err != nil {
		return Verification{}, fmt.Errorf("read audit chain: %w", err)
	}
	defer rows.Close()
	v := auditlog.NewVerifier()
	for rows.Next() {
		e, prev, sum, err := scan(rows)
		if err != nil {
			return Verification{}, err
		}
		v.Next(e.Seq, auditlog.Entry{
			ID: e.ID, At: e.At, ActorType: e.ActorType, ActorID: e.ActorID, ActorName: e.ActorName,
			Action: e.Action, ResourceType: e.ResourceType, ResourceID: e.ResourceID, ProjectID: e.ProjectID,
			Outcome: e.Outcome, RequestID: e.RequestID, Details: e.Details,
		}, prev, sum)
	}
	if err := rows.Err(); err != nil {
		return Verification{}, err
	}
	entries, bad := v.Result()
	return Verification{Valid: bad == 0, Entries: entries, FirstInvalidSeq: bad, CheckedAt: l.now().UTC()}, nil
}

func scan(row pgx.Row) (Entry, []byte, []byte, error) {
	var (
		e             Entry
		details       []byte
		prevHash, sum []byte
	)
	err := row.Scan(&e.Seq, &e.ID, &e.At, &e.ActorType, &e.ActorID, &e.ActorName, &e.Action, &e.ResourceType,
		&e.ResourceID, &e.ProjectID, &e.Outcome, &e.RequestID, &details, &prevHash, &sum)
	if err != nil {
		return Entry{}, nil, nil, fmt.Errorf("scan audit entry: %w", err)
	}
	e.At = e.At.UTC()
	e.Details = map[string]string{}
	if err := json.Unmarshal(details, &e.Details); err != nil {
		return Entry{}, nil, nil, fmt.Errorf("decode audit details: %w", err)
	}
	e.PrevHash = hex.EncodeToString(prevHash)
	e.Hash = hex.EncodeToString(sum)
	return e, prevHash, sum, nil
}

// SchemaSQL returns the DDL of an audit table for schema, with the
// append-only triggers. Migrations embed its output verbatim; a test
// checks that they still match.
func SchemaSQL(schema string) string {
	if !schemaPattern.MatchString(schema) {
		panic("pgaudit: invalid schema name " + schema)
	}
	return fmt.Sprintf(`CREATE TABLE %[1]s.audit_log (
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
CREATE INDEX audit_log_resource ON %[1]s.audit_log (resource_type, resource_id);
CREATE FUNCTION %[1]s.audit_log_is_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '%[1]s.audit_log is append-only';
END
$$;
CREATE TRIGGER audit_log_no_update_or_delete BEFORE UPDATE OR DELETE ON %[1]s.audit_log
    FOR EACH ROW EXECUTE FUNCTION %[1]s.audit_log_is_append_only();
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON %[1]s.audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION %[1]s.audit_log_is_append_only();
`, schema)
}
