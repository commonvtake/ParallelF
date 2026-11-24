package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/pkg/ngsensor"
	"github.com/commonvtake/parallelf/services/netguard/internal/attribution"
	"github.com/commonvtake/parallelf/services/netguard/internal/detect"
	"github.com/commonvtake/parallelf/services/netguard/internal/domain"
)

// DetectBatch is how many events one detection step reads.
const DetectBatch = 2000

// DetectResult reports one detection step.
type DetectResult struct {
	Events   int
	Findings int
	Raised   int
}

// Detect runs the detectors over the next unprocessed events.
func (s *Postgres) Detect(ctx context.Context) (DetectResult, error) {
	var res DetectResult
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var pos int64
		if err := tx.QueryRow(ctx, `SELECT position FROM netguard.cursors WHERE name = 'detect' FOR UPDATE`).Scan(&pos); err != nil {
			return fmt.Errorf("detect cursor: %w", err)
		}
		batch, err := collectEvents(tx.Query(ctx, `SELECT `+eventColumns+` FROM netguard.events e WHERE e.id > $1 ORDER BY e.id LIMIT $2`, pos, DetectBatch))
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		res.Events = len(batch)
		in, err := s.inputs(ctx, tx, batch)
		if err != nil {
			return err
		}
		findings := detect.Run(batch, in)
		res.Findings = len(findings)
		if err := s.updateAssets(ctx, tx, batch, in.Monitored); err != nil {
			return err
		}
		for _, f := range findings {
			raised, err := s.raise(ctx, tx, f)
			if err != nil {
				return err
			}
			if raised {
				res.Raised++
			}
		}
		_, err = tx.Exec(ctx, `UPDATE netguard.cursors SET position = $1 WHERE name = 'detect'`, batch[len(batch)-1].ID)
		return err
	})
	return res, err
}

// monitored returns the configured ranges plus every live Cloud network.
func (s *Postgres) monitored(ctx context.Context, q querier) (all, labs []netip.Prefix, err error) {
	all = slices.Clone(s.opts.Monitored)
	rows, err := q.Query(ctx, `SELECT cidr::text, kind FROM netguard.networks WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, nil, fmt.Errorf("networks: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var c, kind string
		if err := rows.Scan(&c, &kind); err != nil {
			return nil, nil, err
		}
		p, perr := netip.ParsePrefix(c)
		if perr != nil {
			continue
		}
		all = append(all, p)
		if kind == "lab" {
			labs = append(labs, p)
		}
	}
	return all, labs, rows.Err()
}

func addrSet(ctx context.Context, tx pgx.Tx, sql string, ips []string) (map[string]bool, error) {
	out := map[string]bool{}
	rows, err := tx.Query(ctx, sql, ips)
	if err != nil {
		return nil, fmt.Errorf("address lookup: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out[ip] = true
	}
	return out, rows.Err()
}

func (s *Postgres) inputs(ctx context.Context, tx pgx.Tx, batch []domain.Event) (detect.Inputs, error) {
	var in detect.Inputs
	var err error
	in.Monitored, in.LabNetworks, err = s.monitored(ctx, tx)
	if err != nil {
		return in, err
	}
	var ips, flowSrcs []string
	seen := map[string]bool{}
	latest := batch[0].Time
	for _, e := range batch {
		for _, ip := range []string{e.SrcIP, e.DstIP} {
			if ip != "" && !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
		if e.Kind == ngsensor.KindFlow && e.SrcIP != "" && !slices.Contains(flowSrcs, e.SrcIP) {
			flowSrcs = append(flowSrcs, e.SrcIP)
		}
		if e.Time.After(latest) {
			latest = e.Time
		}
	}
	if in.Seen, err = addrSet(ctx, tx, `SELECT host(ip) FROM netguard.assets WHERE ip = ANY($1::text[]::inet[])`, ips); err != nil {
		return in, err
	}
	if in.Attributed, err = addrSet(ctx, tx, `SELECT DISTINCT host(ip) FROM netguard.attributions WHERE valid_to IS NULL AND ip = ANY($1::text[]::inet[])`, ips); err != nil {
		return in, err
	}
	last := batch[len(batch)-1].ID
	since := latest.Add(-detect.ScanWindow)
	if len(flowSrcs) > 0 {
		if in.Vertical, err = scanCounts(ctx, tx, `
			SELECT host(src_ip), host(dst_ip), 0, count(DISTINCT dst_port), max(id), max(ts) FROM netguard.events
			WHERE kind = 'flow' AND src_ip = ANY($1::text[]::inet[]) AND ts > $2 AND id <= $3 AND dst_port IS NOT NULL AND dst_ip IS NOT NULL
			GROUP BY src_ip, dst_ip HAVING count(DISTINCT dst_port) >= $4`, flowSrcs, since, last); err != nil {
			return in, err
		}
		if in.Horizontal, err = scanCounts(ctx, tx, `
			SELECT host(src_ip), '', dst_port, count(DISTINCT dst_ip), max(id), max(ts) FROM netguard.events
			WHERE kind = 'flow' AND src_ip = ANY($1::text[]::inet[]) AND ts > $2 AND id <= $3 AND dst_port IS NOT NULL AND dst_ip IS NOT NULL
			GROUP BY src_ip, dst_port HAVING count(DISTINCT dst_ip) >= $4`, flowSrcs, since, last); err != nil {
			return in, err
		}
	}
	rows, err := tx.Query(ctx, `SELECT document FROM netguard.scopes WHERE revoked_at IS NULL AND valid_until > $1`, latest.Add(-10*time.Minute))
	if err != nil {
		return in, fmt.Errorf("scopes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			return in, err
		}
		if sc, ok := decodeScope(doc); ok {
			in.Scopes = append(in.Scopes, sc)
		}
	}
	return in, rows.Err()
}

func decodeScope(doc string) (ngsensor.Scope, bool) {
	raw, err := base64.StdEncoding.DecodeString(doc)
	if err != nil {
		return ngsensor.Scope{}, false
	}
	var sc ngsensor.Scope
	return sc, json.Unmarshal(raw, &sc) == nil
}

func scanCounts(ctx context.Context, tx pgx.Tx, sql string, srcs []string, since time.Time, last int64) ([]detect.ScanCount, error) {
	rows, err := tx.Query(ctx, sql, srcs, since, last, detect.ScanThreshold)
	if err != nil {
		return nil, fmt.Errorf("scan counts: %w", err)
	}
	defer rows.Close()
	var out []detect.ScanCount
	for rows.Next() {
		var c detect.ScanCount
		if err := rows.Scan(&c.Src, &c.Dst, &c.Port, &c.Distinct, &c.LastEventID, &c.LastSeen); err != nil {
			return nil, err
		}
		c.LastSeen = c.LastSeen.UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

func inAny(ip string, nets []netip.Prefix) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// updateAssets records every monitored address in the batch, and the open
// ports discovery found.
func (s *Postgres) updateAssets(ctx context.Context, tx pgx.Tx, batch []domain.Event, monitored []netip.Prefix) error {
	type agg struct {
		first, last time.Time
		iface       string
		n           int64
		ports       []int32
	}
	seen := map[string]*agg{}
	var order []string
	note := func(ip string, e domain.Event) *agg {
		if ip == "" || !inAny(ip, monitored) {
			return nil
		}
		a, ok := seen[ip]
		if !ok {
			a = &agg{first: e.Time, last: e.Time, iface: e.Interface}
			seen[ip] = a
			order = append(order, ip)
		}
		a.n++
		if e.Time.Before(a.first) {
			a.first = e.Time
		}
		if e.Time.After(a.last) {
			a.last = e.Time
		}
		return a
	}
	for _, e := range batch {
		if e.Kind == ngsensor.KindDiscovery {
			if a := note(e.DstIP, e); a != nil && e.Details["discovery.result"] == "open" && e.DstPort > 0 {
				a.ports = append(a.ports, int32(e.DstPort)) //nolint:gosec // validated port
			}
			continue
		}
		note(e.SrcIP, e)
		note(e.DstIP, e)
	}
	for _, ip := range order {
		a := seen[ip]
		ports := a.ports
		if ports == nil {
			ports = []int32{}
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO netguard.assets AS a (ip, first_seen_at, last_seen_at, first_iface, events, open_ports)
			VALUES ($1::inet, $2, $3, $4, $5, $6::int[])
			ON CONFLICT (ip) DO UPDATE SET last_seen_at = greatest(a.last_seen_at, EXCLUDED.last_seen_at),
				events = a.events + EXCLUDED.events,
				open_ports = ARRAY(SELECT DISTINCT p FROM unnest(a.open_ports || EXCLUDED.open_ports) p ORDER BY p)`,
			ip, a.first, a.last, a.iface, a.n, ports)
		if err != nil {
			return fmt.Errorf("upsert asset: %w", err)
		}
	}
	return nil
}

// partyAt returns who held ip at t.
func partyAt(ctx context.Context, q pgx.Tx, ip string, t time.Time) (*domain.Party, error) {
	if ip == "" {
		return nil, nil
	}
	p := domain.Party{IP: ip, Kind: "unknown"}
	err := q.QueryRow(ctx, `SELECT kind, entity_id, name, COALESCE(project_id::text, ''), owner_subject FROM netguard.attributions
		WHERE ip = $1::inet AND valid_from <= $2 AND (valid_to IS NULL OR valid_to > $2)
		ORDER BY valid_from DESC LIMIT 1`, ip, t).Scan(&p.Kind, &p.EntityID, &p.Name, &p.ProjectID, &p.OwnerSubject)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("attribution: %w", err)
	}
	return &p, nil
}

// raise folds a finding into its live alert, or opens a new alert.
func (s *Postgres) raise(ctx context.Context, tx pgx.Tx, f detect.Finding) (bool, error) {
	now := s.now()
	var id, status, severity string
	var until *time.Time
	err := tx.QueryRow(ctx, `SELECT id::text, status, severity, suppressed_until FROM netguard.alerts
		WHERE dedupe_key = $1 AND status IN ('open', 'acknowledged', 'suppressed') FOR UPDATE`, f.DedupeKey).Scan(&id, &status, &severity, &until)
	switch {
	case err == nil && status == domain.AlertSuppressed && until != nil && !until.After(now):
		// The suppression ran out: close the muted alert and raise afresh.
		if _, err := tx.Exec(ctx, `UPDATE netguard.alerts SET status = 'closed', suppressed_until = NULL,
			status_reason = 'suppression expired', status_by = 'system' WHERE id = $1::text::uuid`, id); err != nil {
			return false, fmt.Errorf("end suppression: %w", err)
		}
	case err == nil:
		if domain.SeverityRank(f.Severity) > domain.SeverityRank(severity) {
			severity = f.Severity
		}
		_, err := tx.Exec(ctx, `UPDATE netguard.alerts SET count = count + 1, severity = $2,
			last_seen_at = greatest(last_seen_at, $3), last_event_id = greatest(last_event_id, $4) WHERE id = $1::text::uuid`,
			id, severity, f.Time, f.EventID)
		if err != nil {
			return false, fmt.Errorf("fold alert: %w", err)
		}
		return false, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return false, fmt.Errorf("find alert: %w", err)
	}
	src, err := partyAt(ctx, tx, f.SrcIP, f.Time)
	if err != nil {
		return false, err
	}
	dst, err := partyAt(ctx, tx, f.DstIP, f.Time)
	if err != nil {
		return false, err
	}
	a := domain.Alert{
		ID: s.opts.NewID(), Detector: f.Detector, RuleID: f.RuleID, Severity: f.Severity, Title: f.Title,
		SrcIP: f.SrcIP, DstIP: f.DstIP, Status: domain.AlertOpen, Count: 1, FirstSeenAt: f.Time, LastSeenAt: f.Time,
		FirstEventID: f.EventID, LastEventID: f.EventID, Details: f.Details,
		Attribution: domain.Attribution{Source: src, Destination: dst},
	}
	details, _ := json.Marshal(a.Details)
	attr, _ := json.Marshal(a.Attribution)
	_, err = tx.Exec(ctx, `
		INSERT INTO netguard.alerts (id, detector, rule_id, severity, title, src_ip, dst_ip, dedupe_key, first_seen_at, last_seen_at,
		                             first_event_id, last_event_id, details, attribution)
		VALUES ($1::text::uuid, $2, $3, $4, $5, NULLIF($6, '')::inet, NULLIF($7, '')::inet, $8, $9, $9, $10, $10, $11, $12)`,
		a.ID, a.Detector, a.RuleID, a.Severity, a.Title, a.SrcIP, a.DstIP, f.DedupeKey, f.Time, nullID(f.EventID), details, attr)
	if err != nil {
		return false, fmt.Errorf("insert alert: %w", err)
	}
	evt, eerr := s.opts.Encoder.AlertRaised(a)
	return true, s.emit(ctx, tx, evt, eerr)
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// --- Attribution from Cloud and VPN events ------------------------------------------------

// ConsumeResult reports one consumption step.
type ConsumeResult struct {
	Applied int
	Skipped int
}

// Consume applies new Cloud and VPN outbox events to the attribution
// tables. Rows are matched by id, so events that commit out of creation
// order are still applied, exactly once.
func (s *Postgres) Consume(ctx context.Context, source string) (ConsumeResult, error) {
	var res ConsumeResult
	if source != "cloud" && source != "vpn" {
		return res, fmt.Errorf("unknown source %q", source)
	}
	type row struct {
		id, subject string
		payload     []byte
	}
	rows, err := s.pool.Query(ctx, `SELECT o.id::text, o.subject, o.payload FROM `+source+`.outbox o
		WHERE o.subject = ANY($1) AND NOT EXISTS (
			SELECT 1 FROM netguard.consumed c WHERE c.source = $2 AND c.event_id = o.id)
		ORDER BY o.created_at, o.id LIMIT 500`, attribution.Subjects, source)
	if err != nil {
		return res, fmt.Errorf("read %s.outbox: %w", source, err)
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.subject, &r.payload); err != nil {
			rows.Close()
			return res, err
		}
		pending = append(pending, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}
	for _, r := range pending {
		c, ok, derr := attribution.Decode(r.subject, r.payload)
		err := s.inTx(ctx, func(tx pgx.Tx) error {
			if derr == nil && ok {
				if err := s.apply(ctx, tx, c, source+":"+r.id); err != nil {
					return err
				}
			}
			_, err := tx.Exec(ctx, `INSERT INTO netguard.consumed (source, event_id, subject, applied) VALUES ($1, $2::text::uuid, $3, $4)
				ON CONFLICT DO NOTHING`, source, r.id, r.subject, s.now())
			return err
		})
		if err != nil {
			return res, err
		}
		if derr != nil || !ok {
			res.Skipped++
		} else {
			res.Applied++
		}
	}
	return res, nil
}

func (s *Postgres) apply(ctx context.Context, tx pgx.Tx, c attribution.Change, ref string) error {
	if n := c.Network; n != nil {
		var project any
		if n.ProjectID != "" {
			project = n.ProjectID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO netguard.networks (id, project_id, name, kind, cidr, created_at)
			VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5::cidr, $6) ON CONFLICT (id) DO NOTHING`,
			n.ID, project, n.Name, n.Kind, n.CIDR, n.At); err != nil {
			return fmt.Errorf("network: %w", err)
		}
	}
	if d := c.NetworkDeleted; d != nil {
		if _, err := tx.Exec(ctx, `UPDATE netguard.networks SET deleted_at = $2 WHERE id = $1::text::uuid AND deleted_at IS NULL`, d.EntityID, d.At); err != nil {
			return fmt.Errorf("network deleted: %w", err)
		}
	}
	for _, cl := range c.Claims {
		var project any
		if cl.ProjectID != "" {
			project = cl.ProjectID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO netguard.attributions (ip, kind, entity_id, name, project_id, owner_subject, valid_from, source_event)
			VALUES ($1::inet, $2, $3, $4, $5::text::uuid, $6, $7, $8) ON CONFLICT DO NOTHING`,
			cl.IP, cl.Kind, cl.EntityID, cl.Name, project, cl.OwnerSubject, cl.At, ref); err != nil {
			return fmt.Errorf("claim: %w", err)
		}
	}
	for _, r := range c.Releases {
		if _, err := tx.Exec(ctx, `UPDATE netguard.attributions SET valid_to = greatest($3, valid_from)
			WHERE kind = $1 AND entity_id = $2 AND valid_to IS NULL`, r.Kind, r.EntityID, r.At); err != nil {
			return fmt.Errorf("release: %w", err)
		}
	}
	return nil
}

// EnsureInfrastructure records the platform's own addresses (the VPN
// gateway's tunnel address, for example) as attributed.
func (s *Postgres) EnsureInfrastructure(ctx context.Context, addrs map[string]string) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		for ip, name := range addrs {
			_, err := tx.Exec(ctx, `INSERT INTO netguard.attributions (ip, kind, entity_id, name, valid_from, source_event)
				VALUES ($1::inet, 'infrastructure', $1, $2, '2000-01-01T00:00:00Z', 'config') ON CONFLICT DO NOTHING`, ip, name)
			if err != nil {
				return fmt.Errorf("infrastructure address %s: %w", ip, err)
			}
		}
		return nil
	})
}

// Assets lists addresses seen on monitored networks with their current
// attribution.
func (s *Postgres) Assets(ctx context.Context) ([]domain.Asset, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT host(a.ip), a.first_seen_at, a.last_seen_at, a.first_iface, a.events, a.open_ports,
		       COALESCE(t.kind, 'unknown'), COALESCE(t.entity_id, ''), COALESCE(t.name, ''), COALESCE(t.project_id::text, ''), COALESCE(t.owner_subject, '')
		FROM netguard.assets a
		LEFT JOIN LATERAL (SELECT * FROM netguard.attributions t WHERE t.ip = a.ip AND t.valid_to IS NULL
		                   ORDER BY t.valid_from DESC LIMIT 1) t ON true
		ORDER BY a.ip LIMIT 2000`)
	if err != nil {
		return nil, fmt.Errorf("assets: %w", err)
	}
	defer rows.Close()
	out := []domain.Asset{}
	for rows.Next() {
		var a domain.Asset
		var ports []int32
		if err := rows.Scan(&a.IP, &a.FirstSeenAt, &a.LastSeenAt, &a.FirstIface, &a.Events, &ports,
			&a.Party.Kind, &a.Party.EntityID, &a.Party.Name, &a.Party.ProjectID, &a.Party.OwnerSubject); err != nil {
			return nil, err
		}
		a.Party.IP = a.IP
		a.FirstSeenAt, a.LastSeenAt = a.FirstSeenAt.UTC(), a.LastSeenAt.UTC()
		a.OpenPorts = make([]int, 0, len(ports))
		for _, p := range ports {
			a.OpenPorts = append(a.OpenPorts, int(p))
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// OwnedRanges are the ranges scopes may cover: configured ranges and live
// Cloud networks.
func (s *Postgres) OwnedRanges(ctx context.Context) ([]netip.Prefix, error) {
	all, _, err := s.monitored(ctx, s.pool)
	return all, err
}
