// Package store persists pf-core data in PostgreSQL using pgx.
//
// Every state change and its outbox event are written in one transaction,
// so an event exists if and only if the change committed.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/commonvtake/parallelf/services/core/internal/projects"
)

const uniqueViolation = "23505"

// Postgres implements projects.Store.
type Postgres struct {
	pool *pgxpool.Pool
}

// Open creates a connection pool. Connections are established lazily; use
// Ping to check that the database is reachable.
func Open(ctx context.Context, databaseURL string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		// The parse error can echo the URL, which contains the password.
		return nil, errors.New("PF_DATABASE_URL is not a valid PostgreSQL connection string")
	}
	cfg.MaxConns = 8
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

// Close releases every pooled connection.
func (s *Postgres) Close() { s.pool.Close() }

// Ping reports whether the database answers. It is the readiness check.
func (s *Postgres) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

const projectColumns = `id::text, slug, name, description, created_by, created_at, updated_at`

func scanProject(row pgx.Row) (projects.Project, error) {
	var p projects.Project
	err := row.Scan(&p.ID, &p.Slug, &p.Name, &p.Description, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return projects.Project{}, err
	}
	p.CreatedAt = p.CreatedAt.UTC()
	p.UpdatedAt = p.UpdatedAt.UTC()
	return p, nil
}

// Create inserts the project and its event atomically.
func (s *Postgres) Create(ctx context.Context, p projects.Project, evt projects.OutboxEvent) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO core.projects (id, slug, name, description, created_by, created_at, updated_at)
			VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7)`,
			p.ID, p.Slug, p.Name, p.Description, p.CreatedBy, p.CreatedAt, p.UpdatedAt)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
				return projects.ErrSlugTaken
			}
			return fmt.Errorf("insert project: %w", err)
		}
		return insertOutbox(ctx, tx, evt)
	})
}

// Get returns the project with the given id.
func (s *Postgres) Get(ctx context.Context, id string) (projects.Project, error) {
	p, err := scanProject(s.pool.QueryRow(ctx,
		`SELECT `+projectColumns+` FROM core.projects WHERE id = $1::text::uuid`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return projects.Project{}, projects.ErrNotFound
	}
	if err != nil {
		return projects.Project{}, fmt.Errorf("select project: %w", err)
	}
	return p, nil
}

// List returns up to limit projects with id greater than after.
func (s *Postgres) List(ctx context.Context, after string, limit int) ([]projects.Project, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+projectColumns+`
		FROM core.projects
		WHERE ($1::text = '' OR id > NULLIF($1::text, '')::uuid)
		ORDER BY id
		LIMIT $2`, after, limit)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	var out []projects.Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, fmt.Errorf("scan project: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	return out, nil
}

// Delete removes the project and records the event atomically.
func (s *Postgres) Delete(ctx context.Context, id string, evt projects.OutboxEvent) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM core.projects WHERE id = $1::text::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete project: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return projects.ErrNotFound
		}
		return insertOutbox(ctx, tx, evt)
	})
}

func insertOutbox(ctx context.Context, tx pgx.Tx, evt projects.OutboxEvent) error {
	headers, err := json.Marshal(evt.Headers)
	if err != nil {
		return fmt.Errorf("encode event headers: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO core.outbox (id, subject, event_type, payload, headers)
		VALUES ($1::text::uuid, $2, $3, $4, $5::text::jsonb)`,
		evt.ID, evt.Subject, evt.Type, evt.Payload, string(headers))
	if err != nil {
		return fmt.Errorf("insert outbox event: %w", err)
	}
	return nil
}

// inTx runs fn in a transaction, committing only when fn returns nil.
func (s *Postgres) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}
