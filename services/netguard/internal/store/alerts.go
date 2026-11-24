package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/services/netguard/internal/domain"
)

const alertColumns = `a.id::text, a.detector, a.rule_id, a.severity, a.title, COALESCE(host(a.src_ip), ''), COALESCE(host(a.dst_ip), ''),
	a.status, a.count, a.first_seen_at, a.last_seen_at, COALESCE(a.first_event_id, 0), COALESCE(a.last_event_id, 0),
	a.details, a.attribution, COALESCE(a.incident_id::text, ''), a.status_reason, a.status_by, a.suppressed_until`

func scanAlert(row pgx.Row) (domain.Alert, error) {
	var a domain.Alert
	var details, attr []byte
	err := row.Scan(&a.ID, &a.Detector, &a.RuleID, &a.Severity, &a.Title, &a.SrcIP, &a.DstIP, &a.Status, &a.Count,
		&a.FirstSeenAt, &a.LastSeenAt, &a.FirstEventID, &a.LastEventID, &details, &attr, &a.IncidentID,
		&a.StatusReason, &a.StatusBy, &a.SuppressedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Alert{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Alert{}, fmt.Errorf("scan alert: %w", err)
	}
	a.FirstSeenAt, a.LastSeenAt = a.FirstSeenAt.UTC(), a.LastSeenAt.UTC()
	a.Details = jsonMap(details)
	_ = json.Unmarshal(attr, &a.Attribution)
	return a, nil
}

func collectAlerts(rows pgx.Rows, err error) ([]domain.Alert, error) {
	if err != nil {
		return nil, fmt.Errorf("query alerts: %w", err)
	}
	defer rows.Close()
	out := []domain.Alert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListAlerts returns alerts, most recently seen first.
func (s *Postgres) ListAlerts(ctx context.Context, f domain.AlertFilter) ([]domain.Alert, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	minRank := max(domain.SeverityRank(f.Severity), 0)
	var ip any
	if f.IP != "" {
		ip = f.IP
	}
	return collectAlerts(s.pool.Query(ctx, `SELECT `+alertColumns+` FROM netguard.alerts a
		WHERE ($1::text = '' OR a.status = $1)
		  AND ($2::text = '' OR a.detector = $2)
		  AND array_position($3::text[], a.severity) - 1 >= $4
		  AND ($5::inet IS NULL OR a.src_ip = $5::inet OR a.dst_ip = $5::inet)
		ORDER BY a.last_seen_at DESC LIMIT $6`, f.Status, f.Detector, domain.Severities, minRank, ip, f.Limit))
}

// GetAlert returns one alert.
func (s *Postgres) GetAlert(ctx context.Context, id string) (domain.Alert, error) {
	return scanAlert(s.pool.QueryRow(ctx, `SELECT `+alertColumns+` FROM netguard.alerts a WHERE a.id = $1::text::uuid`, id))
}

// AlertEvents returns the telemetry behind an alert: its first and last
// events, and the traffic between its addresses while it was active.
func (s *Postgres) AlertEvents(ctx context.Context, a domain.Alert, limit int) ([]domain.Event, error) {
	return collectEvents(s.pool.Query(ctx, `SELECT `+eventColumns+` FROM netguard.events e
		WHERE e.id IN ($1, $2)
		   OR ($3 <> '' AND e.src_ip = NULLIF($3, '')::inet AND ($4 = '' OR e.dst_ip = NULLIF($4, '')::inet)
		       AND e.ts BETWEEN $5 AND $6)
		ORDER BY e.id LIMIT $7`, a.FirstEventID, a.LastEventID, a.SrcIP, a.DstIP,
		a.FirstSeenAt.Add(-detectWindowSlack), a.LastSeenAt.Add(detectWindowSlack), limit))
}

// ChangeAlert applies an analyst's decision.
func (s *Postgres) ChangeAlert(ctx context.Context, id string, c domain.AlertChange, actor domain.Actor) (domain.Alert, error) {
	var a domain.Alert
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var err error
		a, err = scanAlert(tx.QueryRow(ctx, `SELECT `+alertColumns+` FROM netguard.alerts a WHERE a.id = $1::text::uuid FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if !domain.CanTransitionAlert(a.Status, c.Status) {
			return domain.ErrInvalidState
		}
		from := a.Status
		now := s.now()
		var until any
		if c.Status == domain.AlertSuppressed {
			t := now.Add(c.SuppressFor)
			until = t
			a.SuppressedUntil = &t
		} else {
			a.SuppressedUntil = nil
		}
		a.Status, a.StatusReason, a.StatusBy = c.Status, c.Reason, actor.Label()
		_, err = tx.Exec(ctx, `UPDATE netguard.alerts SET status = $2, status_reason = $3, status_by = $4, suppressed_until = $5
			WHERE id = $1::text::uuid`, id, a.Status, a.StatusReason, a.StatusBy, until)
		if code, constraint := pgCode(err); code == "23505" && constraint == "alerts_live" {
			// Lifting a suppression while a newer alert holds the key.
			return domain.ErrInvalidState
		}
		if err != nil {
			return fmt.Errorf("change alert: %w", err)
		}
		evt, eerr := s.opts.Encoder.AlertStatusChanged(a, from, actor.Label(), now)
		if err := s.emit(ctx, tx, evt, eerr); err != nil {
			return err
		}
		details := map[string]string{"from": from, "to": a.Status, "reason": a.StatusReason}
		if a.SuppressedUntil != nil {
			details["suppressed_until"] = a.SuppressedUntil.Format("2006-01-02T15:04:05Z07:00")
		}
		if a.Status != domain.AlertOpen && a.IncidentID != "" {
			if _, err := tx.Exec(ctx, `INSERT INTO netguard.incident_timeline (incident_id, ts, actor, kind, body, ref)
				VALUES ($1::text::uuid, $2, $3, 'status', $4, $5)`, a.IncidentID, now, actor.Label(),
				"Alert "+a.Title+" marked "+a.Status, "alert:"+a.ID); err != nil {
				return err
			}
		}
		return s.appendAudit(ctx, tx, actor, "network.alerts."+a.Status, "alert", a.ID, details)
	})
	return a, err
}
