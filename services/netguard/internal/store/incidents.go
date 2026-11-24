package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/services/netguard/internal/domain"
)

// detectWindowSlack widens an alert's window when collecting its events.
const detectWindowSlack = 60 * time.Second

const incidentColumns = `i.id::text, i.title, i.severity, i.status, i.summary, i.created_by, i.created_at, i.updated_at, i.resolved_at,
	(SELECT count(*) FROM netguard.alerts x WHERE x.incident_id = i.id)`

func scanIncident(row pgx.Row) (domain.Incident, error) {
	var i domain.Incident
	err := row.Scan(&i.ID, &i.Title, &i.Severity, &i.Status, &i.Summary, &i.CreatedBy, &i.CreatedAt, &i.UpdatedAt, &i.ResolvedAt, &i.AlertCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Incident{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Incident{}, fmt.Errorf("scan incident: %w", err)
	}
	i.CreatedAt, i.UpdatedAt = i.CreatedAt.UTC(), i.UpdatedAt.UTC()
	return i, nil
}

// ListIncidents returns incidents, newest first.
func (s *Postgres) ListIncidents(ctx context.Context, status string) ([]domain.Incident, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+incidentColumns+` FROM netguard.incidents i
		WHERE ($1::text = '' OR i.status = $1) ORDER BY i.created_at DESC LIMIT 200`, status)
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()
	out := []domain.Incident{}
	for rows.Next() {
		i, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *Postgres) timeline(ctx context.Context, q pgx.Tx, incidentID string, now time.Time, actor, kind, body, ref string) error {
	_, err := q.Exec(ctx, `INSERT INTO netguard.incident_timeline (incident_id, ts, actor, kind, body, ref)
		VALUES ($1::text::uuid, $2, $3, $4, $5, $6)`, incidentID, now, actor, kind, body, ref)
	if err != nil {
		return fmt.Errorf("timeline: %w", err)
	}
	return nil
}

func (s *Postgres) linkAlerts(ctx context.Context, tx pgx.Tx, incidentID string, alertIDs []string, now time.Time, actor string) error {
	for _, aid := range alertIDs {
		var title string
		err := tx.QueryRow(ctx, `UPDATE netguard.alerts SET incident_id = $2::text::uuid WHERE id = $1::text::uuid RETURNING title`,
			aid, incidentID).Scan(&title)
		if errors.Is(err, pgx.ErrNoRows) {
			return &domain.ValidationError{Errors: []domain.FieldError{{Field: "alert_ids", Code: "not_found", Message: "No alert " + aid + "."}}}
		}
		if err != nil {
			return fmt.Errorf("link alert: %w", err)
		}
		if err := s.timeline(ctx, tx, incidentID, now, actor, "alert_linked", title, "alert:"+aid); err != nil {
			return err
		}
	}
	return nil
}

// CreateIncident opens an incident and links alerts to it.
func (s *Postgres) CreateIncident(ctx context.Context, in domain.IncidentInput, actor domain.Actor) (domain.Incident, error) {
	var inc domain.Incident
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		now := s.now()
		var err error
		inc, err = scanIncident(tx.QueryRow(ctx, `
			INSERT INTO netguard.incidents AS i (id, title, severity, summary, created_by, created_at, updated_at)
			VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $6) RETURNING `+incidentColumns,
			s.opts.NewID(), strings.TrimSpace(in.Title), in.Severity, in.Summary, actor.Label(), now))
		if err != nil {
			return fmt.Errorf("create incident: %w", err)
		}
		if err := s.timeline(ctx, tx, inc.ID, now, actor.Label(), "opened", inc.Title, ""); err != nil {
			return err
		}
		if err := s.linkAlerts(ctx, tx, inc.ID, in.AlertIDs, now, actor.Label()); err != nil {
			return err
		}
		inc.AlertCount = len(in.AlertIDs)
		evt, eerr := s.opts.Encoder.IncidentChanged(inc, "", actor.Label(), now)
		if err := s.emit(ctx, tx, evt, eerr); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, "network.incidents.create", "incident", inc.ID,
			map[string]string{"title": inc.Title, "severity": inc.Severity, "alerts": strings.Join(in.AlertIDs, ",")})
	})
	return inc, err
}

// UpdateIncident changes status, adds a note or links alerts.
func (s *Postgres) UpdateIncident(ctx context.Context, id string, u domain.IncidentUpdate, actor domain.Actor) (domain.Incident, error) {
	var inc domain.Incident
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		now := s.now()
		var err error
		inc, err = scanIncident(tx.QueryRow(ctx, `SELECT `+incidentColumns+` FROM netguard.incidents i WHERE i.id = $1::text::uuid FOR UPDATE`, id))
		if err != nil {
			return err
		}
		from := inc.Status
		if u.Status != "" && u.Status != inc.Status {
			if !domain.CanTransitionIncident(inc.Status, u.Status) {
				return domain.ErrInvalidState
			}
			inc.Status = u.Status
			if u.Status == domain.IncidentResolved {
				inc.ResolvedAt = &now
			} else {
				inc.ResolvedAt = nil
			}
			if err := s.timeline(ctx, tx, id, now, actor.Label(), "status", from+" → "+inc.Status, ""); err != nil {
				return err
			}
		}
		if strings.TrimSpace(u.Note) != "" {
			if err := s.timeline(ctx, tx, id, now, actor.Label(), "note", u.Note, ""); err != nil {
				return err
			}
		}
		if err := s.linkAlerts(ctx, tx, id, u.AlertIDs, now, actor.Label()); err != nil {
			return err
		}
		inc.UpdatedAt = now
		if _, err := tx.Exec(ctx, `UPDATE netguard.incidents SET status = $2, resolved_at = $3, updated_at = $4 WHERE id = $1::text::uuid`,
			id, inc.Status, inc.ResolvedAt, now); err != nil {
			return fmt.Errorf("update incident: %w", err)
		}
		inc.AlertCount += len(u.AlertIDs)
		if from != inc.Status {
			evt, eerr := s.opts.Encoder.IncidentChanged(inc, from, actor.Label(), now)
			if err := s.emit(ctx, tx, evt, eerr); err != nil {
				return err
			}
		}
		details := map[string]string{"status": inc.Status}
		if u.Note != "" {
			details["note"] = "added"
		}
		if len(u.AlertIDs) > 0 {
			details["alerts_linked"] = strings.Join(u.AlertIDs, ",")
		}
		return s.appendAudit(ctx, tx, actor, "network.incidents.update", "incident", id, details)
	})
	return inc, err
}

// GetIncident returns an incident with its alerts, timeline and evidence.
func (s *Postgres) GetIncident(ctx context.Context, id string) (domain.IncidentDetail, error) {
	var d domain.IncidentDetail
	var err error
	d.Incident, err = scanIncident(s.pool.QueryRow(ctx, `SELECT `+incidentColumns+` FROM netguard.incidents i WHERE i.id = $1::text::uuid`, id))
	if err != nil {
		return d, err
	}
	if d.Alerts, err = collectAlerts(s.pool.Query(ctx, `SELECT `+alertColumns+` FROM netguard.alerts a
		WHERE a.incident_id = $1::text::uuid ORDER BY a.first_seen_at`, id)); err != nil {
		return d, err
	}
	rows, err := s.pool.Query(ctx, `SELECT id, ts, actor, kind, body, ref FROM netguard.incident_timeline
		WHERE incident_id = $1::text::uuid ORDER BY id`, id)
	if err != nil {
		return d, fmt.Errorf("timeline: %w", err)
	}
	defer rows.Close()
	d.Timeline = []domain.TimelineEntry{}
	for rows.Next() {
		var t domain.TimelineEntry
		if err := rows.Scan(&t.ID, &t.Time, &t.Actor, &t.Kind, &t.Body, &t.Ref); err != nil {
			return d, err
		}
		t.Time = t.Time.UTC()
		d.Timeline = append(d.Timeline, t)
	}
	if err := rows.Err(); err != nil {
		return d, err
	}
	d.Evidence, err = s.ListEvidence(ctx, id)
	return d, err
}

// --- Evidence ------------------------------------------------------------------------------

const evidenceColumns = `v.id::text, v.incident_id::text, v.kind, v.name, v.media_type, length(v.content), encode(v.sha256, 'hex'),
	v.ref, v.added_by, v.added_at`

func scanEvidence(row pgx.Row) (domain.Evidence, error) {
	var e domain.Evidence
	err := row.Scan(&e.ID, &e.IncidentID, &e.Kind, &e.Name, &e.MediaType, &e.Size, &e.SHA256, &e.Ref, &e.AddedBy, &e.AddedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Evidence{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Evidence{}, fmt.Errorf("scan evidence: %w", err)
	}
	e.AddedAt = e.AddedAt.UTC()
	return e, nil
}

// ListEvidence returns an incident's evidence (without content).
func (s *Postgres) ListEvidence(ctx context.Context, incidentID string) ([]domain.Evidence, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+evidenceColumns+` FROM netguard.evidence v WHERE v.incident_id = $1::text::uuid ORDER BY v.added_at, v.id`, incidentID)
	if err != nil {
		return nil, fmt.Errorf("list evidence: %w", err)
	}
	defer rows.Close()
	out := []domain.Evidence{}
	for rows.Next() {
		e, err := scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AddEvidence attaches an item. Events and alerts are captured as they are
// stored now; their digest pins that content.
func (s *Postgres) AddEvidence(ctx context.Context, incidentID string, in domain.EvidenceInput, actor domain.Actor) (domain.Evidence, error) {
	var ev domain.Evidence
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		now := s.now()
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM netguard.incidents WHERE id = $1::text::uuid FOR UPDATE`, incidentID).Scan(&status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return domain.ErrNotFound
			}
			return err
		}
		if status == domain.IncidentResolved {
			return domain.ErrInvalidState
		}
		content, media, ref := in.Content, in.MediaType, ""
		switch in.Kind {
		case "event":
			id, err := strconv.ParseInt(in.Ref, 10, 64)
			if err != nil {
				return &domain.ValidationError{Errors: []domain.FieldError{{Field: "ref", Code: "format", Message: "An event id."}}}
			}
			e, err := scanEvent(tx.QueryRow(ctx, `SELECT `+eventColumns+` FROM netguard.events e WHERE e.id = $1`, id))
			if errors.Is(err, domain.ErrNotFound) {
				return &domain.ValidationError{Errors: []domain.FieldError{{Field: "ref", Code: "not_found", Message: "No such event."}}}
			}
			if err != nil {
				return err
			}
			content, _ = json.MarshalIndent(e, "", "  ")
			media, ref = "application/json", "event:"+in.Ref
		case "alert":
			a, err := scanAlert(tx.QueryRow(ctx, `SELECT `+alertColumns+` FROM netguard.alerts a WHERE a.id = $1::text::uuid`, in.Ref))
			if errors.Is(err, domain.ErrNotFound) {
				return &domain.ValidationError{Errors: []domain.FieldError{{Field: "ref", Code: "not_found", Message: "No such alert."}}}
			}
			if err != nil {
				return err
			}
			content, _ = json.MarshalIndent(a, "", "  ")
			media, ref = "application/json", "alert:"+in.Ref
		case "note":
			media = "text/plain; charset=utf-8"
		}
		sum := sha256.Sum256(content)
		var err error
		ev, err = scanEvidence(tx.QueryRow(ctx, `
			INSERT INTO netguard.evidence AS v (id, incident_id, kind, name, media_type, content, sha256, ref, added_by, added_at)
			VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING `+evidenceColumns,
			s.opts.NewID(), incidentID, in.Kind, in.Name, media, content, sum[:], ref, actor.Label(), now))
		if err != nil {
			return fmt.Errorf("add evidence: %w", err)
		}
		if err := s.timeline(ctx, tx, incidentID, now, actor.Label(), "evidence", ev.Name+" (sha256 "+ev.SHA256[:16]+"…)", "evidence:"+ev.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE netguard.incidents SET updated_at = $2 WHERE id = $1::text::uuid`, incidentID, now); err != nil {
			return err
		}
		evt, eerr := s.opts.Encoder.EvidenceAdded(ev)
		if err := s.emit(ctx, tx, evt, eerr); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, actor, "network.evidence.add", "incident", incidentID,
			map[string]string{"evidence_id": ev.ID, "kind": ev.Kind, "sha256": ev.SHA256})
	})
	return ev, err
}

// EvidenceContent returns an item and its content.
func (s *Postgres) EvidenceContent(ctx context.Context, incidentID, evidenceID string) (domain.Evidence, []byte, error) {
	var content []byte
	var e domain.Evidence
	err := s.pool.QueryRow(ctx, `SELECT `+evidenceColumns+`, v.content FROM netguard.evidence v
		WHERE v.id = $1::text::uuid AND v.incident_id = $2::text::uuid`, evidenceID, incidentID).
		Scan(&e.ID, &e.IncidentID, &e.Kind, &e.Name, &e.MediaType, &e.Size, &e.SHA256, &e.Ref, &e.AddedBy, &e.AddedAt, &content)
	if errors.Is(err, pgx.ErrNoRows) {
		return e, nil, domain.ErrNotFound
	}
	if err != nil {
		return e, nil, fmt.Errorf("evidence content: %w", err)
	}
	e.AddedAt = e.AddedAt.UTC()
	return e, content, nil
}

// VerifyEvidence recomputes the digest of every item of an incident.
func (s *Postgres) VerifyEvidence(ctx context.Context, incidentID string) (domain.EvidenceVerification, error) {
	v := domain.EvidenceVerification{Valid: true, Mismatch: []string{}}
	if _, err := scanIncident(s.pool.QueryRow(ctx, `SELECT `+incidentColumns+` FROM netguard.incidents i WHERE i.id = $1::text::uuid`, incidentID)); err != nil {
		return v, err
	}
	rows, err := s.pool.Query(ctx, `SELECT id::text, content, sha256 FROM netguard.evidence WHERE incident_id = $1::text::uuid`, incidentID)
	if err != nil {
		return v, fmt.Errorf("verify evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var content, sum []byte
		if err := rows.Scan(&id, &content, &sum); err != nil {
			return v, err
		}
		v.Checked++
		got := sha256.Sum256(content)
		if hex.EncodeToString(got[:]) != hex.EncodeToString(sum) {
			v.Valid = false
			v.Mismatch = append(v.Mismatch, id)
		}
	}
	return v, rows.Err()
}
