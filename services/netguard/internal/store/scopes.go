package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/pkg/ngsensor"
	"github.com/commonvtake/parallelf/services/netguard/internal/domain"
)

const scopeColumns = `s.id::text, s.name, s.cidrs::text[], s.techniques, s.ports, s.rate_pps, s.authorization_note, s.issued_at,
	s.valid_until, s.created_by, s.revoked_at, s.revoked_by, s.document, s.signature`

func (s *Postgres) scanScope(row pgx.Row) (domain.Scope, error) {
	var x domain.Scope
	var ports []int32
	err := row.Scan(&x.ID, &x.Name, &x.CIDRs, &x.Techniques, &ports, &x.RatePPS, &x.AuthorizationNote, &x.IssuedAt,
		&x.ValidUntil, &x.CreatedBy, &x.RevokedAt, &x.RevokedBy, &x.Signed.Document, &x.Signed.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Scope{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Scope{}, fmt.Errorf("scan scope: %w", err)
	}
	x.IssuedAt, x.ValidUntil = x.IssuedAt.UTC(), x.ValidUntil.UTC()
	x.Ports = make([]int, 0, len(ports))
	for _, p := range ports {
		x.Ports = append(x.Ports, int(p))
	}
	switch {
	case x.RevokedAt != nil:
		x.Status = "revoked"
	case !s.opts.Now().Before(x.ValidUntil):
		x.Status = "expired"
	default:
		x.Status = "active"
	}
	return x, nil
}

// IssueScope validates, signs and stores a discovery scope.
func (s *Postgres) IssueScope(ctx context.Context, in domain.ScopeInput, actor domain.Actor) (domain.Scope, error) {
	owned, err := s.OwnedRanges(ctx)
	if err != nil {
		return domain.Scope{}, err
	}
	now := s.now()
	sc, err := domain.BuildScope(in, s.opts.NewID(), now, owned)
	if err != nil {
		return domain.Scope{}, err
	}
	signed, err := ngsensor.Sign(sc, s.opts.ScopeKey)
	if err != nil {
		return domain.Scope{}, fmt.Errorf("sign scope: %w", err)
	}
	ports := make([]int32, 0, len(sc.Ports))
	for _, p := range sc.Ports {
		ports = append(ports, int32(p)) //nolint:gosec // validated port
	}
	var out domain.Scope
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.scanScope(tx.QueryRow(ctx, `
			INSERT INTO netguard.scopes AS s (id, name, cidrs, techniques, ports, rate_pps, authorization_note, issued_at, valid_until,
			                                  document, signature, created_by)
			VALUES ($1::text::uuid, $2, $3::text[]::cidr[], $4, $5::int[], $6, $7, $8, $9, $10, $11, $12) RETURNING `+scopeColumns,
			sc.ID, sc.Name, sc.CIDRs, sc.Techniques, ports, sc.RatePPS, in.AuthorizationNote, sc.IssuedAt, sc.ValidUntil,
			signed.Document, signed.Signature, actor.Label()))
		if err != nil {
			return fmt.Errorf("issue scope: %w", err)
		}
		evt, eerr := s.opts.Encoder.ScopeChanged(out, "issued", actor.Label(), now)
		if err := s.emit(ctx, tx, evt, eerr); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, "network.scopes.issue", "scope", out.ID, map[string]string{
			"name": out.Name, "cidrs": fmt.Sprint(out.CIDRs), "techniques": fmt.Sprint(out.Techniques), "ports": fmt.Sprint(out.Ports),
			"rate_pps": strconv.Itoa(out.RatePPS), "valid_until": out.ValidUntil.Format("2006-01-02T15:04:05Z"),
			"authorization_note": out.AuthorizationNote,
		})
	})
	return out, err
}

// ListScopes returns every scope, newest first.
func (s *Postgres) ListScopes(ctx context.Context) ([]domain.Scope, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scopeColumns+` FROM netguard.scopes s ORDER BY s.issued_at DESC LIMIT 200`)
	if err != nil {
		return nil, fmt.Errorf("list scopes: %w", err)
	}
	defer rows.Close()
	out := []domain.Scope{}
	for rows.Next() {
		x, err := s.scanScope(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// GetScope returns one scope.
func (s *Postgres) GetScope(ctx context.Context, id string) (domain.Scope, error) {
	return s.scanScope(s.pool.QueryRow(ctx, `SELECT `+scopeColumns+` FROM netguard.scopes s WHERE s.id = $1::text::uuid`, id))
}

// RevokeScope stops a scope from being handed to sensors.
func (s *Postgres) RevokeScope(ctx context.Context, id string, actor domain.Actor) (domain.Scope, error) {
	var out domain.Scope
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		now := s.now()
		var err error
		out, err = s.scanScope(tx.QueryRow(ctx, `UPDATE netguard.scopes s SET revoked_at = $2, revoked_by = $3
			WHERE s.id = $1::text::uuid AND s.revoked_at IS NULL RETURNING `+scopeColumns, id, now, actor.Label()))
		if errors.Is(err, domain.ErrNotFound) {
			if _, gerr := s.scanScope(tx.QueryRow(ctx, `SELECT `+scopeColumns+` FROM netguard.scopes s WHERE s.id = $1::text::uuid`, id)); gerr == nil {
				return domain.ErrInvalidState
			}
			return domain.ErrNotFound
		}
		if err != nil {
			return err
		}
		evt, eerr := s.opts.Encoder.ScopeChanged(out, "revoked", actor.Label(), now)
		if err := s.emit(ctx, tx, evt, eerr); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, "network.scopes.revoke", "scope", id, map[string]string{"name": out.Name})
	})
	return out, err
}
