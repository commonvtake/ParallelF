package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
	"github.com/commonvtake/parallelf/services/cloud/internal/ipam"
	"github.com/commonvtake/parallelf/services/cloud/internal/scheduler"
)

const workloadSelect = `
	SELECT w.id::text, w.project_id::text, w.name, w.kind, w.template_id::text, t.name, t.version,
	       w.flavor_id::text, f.name, w.network_id::text, net.name, COALESCE(w.node_id::text, ''), COALESCE(nd.name, ''),
	       w.vcpus, w.memory_mib, w.disk_gib, host(w.ip), w.mac::text, w.desired_state, w.state,
	       w.generation, w.observed_generation, w.status_message, w.spec, w.created_by,
	       w.created_at, w.updated_at, w.state_changed_at, w.deleted_at
	FROM cloud.workloads w
	JOIN cloud.templates t ON t.id = w.template_id
	JOIN cloud.flavors f ON f.id = w.flavor_id
	JOIN cloud.networks net ON net.id = w.network_id
	LEFT JOIN cloud.nodes nd ON nd.id = w.node_id`

func scanWorkload(row pgx.Row) (domain.Workload, error) {
	var (
		w    domain.Workload
		spec []byte
	)
	err := row.Scan(&w.ID, &w.ProjectID, &w.Name, &w.Kind, &w.TemplateID, &w.TemplateName, &w.TemplateVersion,
		&w.FlavorID, &w.FlavorName, &w.NetworkID, &w.NetworkName, &w.NodeID, &w.NodeName,
		&w.VCPUs, &w.MemoryMiB, &w.DiskGiB, &w.IP, &w.MAC, &w.DesiredState, &w.State,
		&w.Generation, &w.ObservedGeneration, &w.StatusMessage, &spec, &w.CreatedBy,
		&w.CreatedAt, &w.UpdatedAt, &w.StateChangedAt, &w.DeletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Workload{}, domain.ErrNotFound
		}
		return domain.Workload{}, fmt.Errorf("scan workload: %w", err)
	}
	if err := json.Unmarshal(spec, &w.Spec); err != nil {
		return domain.Workload{}, fmt.Errorf("decode workload spec: %w", err)
	}
	w.CreatedAt, w.UpdatedAt, w.StateChangedAt = w.CreatedAt.UTC(), w.UpdatedAt.UTC(), w.StateChangedAt.UTC()
	if w.DeletedAt != nil {
		t := w.DeletedAt.UTC()
		w.DeletedAt = &t
	}
	return w, nil
}

func collectWorkloads(rows pgx.Rows) ([]domain.Workload, error) {
	defer rows.Close()
	out := []domain.Workload{}
	for rows.Next() {
		w, err := scanWorkload(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// lockWorkloads selects workloads FOR UPDATE in id order (a fixed order
// avoids deadlocks between concurrent transactions).
func (s *Postgres) lockWorkloads(ctx context.Context, tx pgx.Tx, where string, args ...any) ([]domain.Workload, error) {
	rows, err := tx.Query(ctx, workloadSelect+` WHERE `+where+` ORDER BY w.id FOR UPDATE OF w`, args...)
	if err != nil {
		return nil, fmt.Errorf("lock workloads: %w", err)
	}
	return collectWorkloads(rows)
}

func (s *Postgres) lockWorkload(ctx context.Context, tx pgx.Tx, id string) (domain.Workload, error) {
	ws, err := s.lockWorkloads(ctx, tx, `w.id = $1::text::uuid`, id)
	if err != nil {
		return domain.Workload{}, err
	}
	if len(ws) == 0 {
		return domain.Workload{}, domain.ErrNotFound
	}
	return ws[0], nil
}

func addEvent(ctx context.Context, tx pgx.Tx, workloadID, typ, msg string, at time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO cloud.workload_events (workload_id, ts, type, message) VALUES ($1::text::uuid, $2, $3, $4)`,
		workloadID, at, typ, msg)
	if err != nil {
		return fmt.Errorf("insert workload event: %w", err)
	}
	return nil
}

// setState records a state transition: the row, the history entry and the
// outbox event. A state of DELETED also releases the workload's address.
func (s *Postgres) setState(ctx context.Context, tx pgx.Tx, w domain.Workload, state, msg string, observed int64, now time.Time) error {
	from := w.State
	stateChanged := state != w.State
	if !stateChanged && msg == w.StatusMessage && observed == w.ObservedGeneration {
		return nil
	}
	var deletedAt *time.Time
	if state == domain.StateDeleted {
		deletedAt = &now
	}
	_, err := tx.Exec(ctx, `
		UPDATE cloud.workloads
		SET state = $2, status_message = $3, observed_generation = $4, updated_at = $5,
		    state_changed_at = CASE WHEN state <> $2 THEN $5 ELSE state_changed_at END,
		    deleted_at = $6
		WHERE id = $1::text::uuid`, w.ID, state, msg, observed, now, deletedAt)
	if err != nil {
		return fmt.Errorf("update workload state: %w", err)
	}
	w.State, w.StatusMessage, w.ObservedGeneration = state, msg, observed

	if stateChanged {
		text := from + " → " + state
		if msg != "" {
			text += ": " + msg
		}
		if err := addEvent(ctx, tx, w.ID, "state", text, now); err != nil {
			return err
		}
		if err := emit(ctx, tx, ev(stateEvent(s.opts.Encoder, w, from, now))); err != nil {
			return err
		}
	} else if msg != "" {
		// Progress or error details while the state stays the same.
		if err := addEvent(ctx, tx, w.ID, "status", msg, now); err != nil {
			return err
		}
	}

	if state == domain.StateDeleted {
		if _, err := tx.Exec(ctx, `DELETE FROM cloud.ip_allocations WHERE workload_id = $1::text::uuid`, w.ID); err != nil {
			return fmt.Errorf("release address: %w", err)
		}
		w.DeletedAt = &now
		if err := emit(ctx, tx, ev(deletedEvent(s.opts.Encoder, w, now))); err != nil {
			return err
		}
	}
	return nil
}

func stateEvent(enc Encoder, w domain.Workload, from string, at time.Time) (domain.OutboxEvent, error) {
	return enc.WorkloadStateChanged(w, from, at)
}

func deletedEvent(enc Encoder, w domain.Workload, at time.Time) (domain.OutboxEvent, error) {
	return enc.WorkloadDeleted(w, at)
}

// CreateWorkload admits a workload: it resolves the template and flavor,
// enforces the project quota, allocates an address and records the
// workload as PENDING for the scheduler.
func (s *Postgres) CreateWorkload(ctx context.Context, in domain.WorkloadInput, actor domain.Actor) (domain.Workload, error) {
	var created domain.Workload
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tmpl, err := s.resolveTemplate(ctx, tx, in.Template, in.TemplateVersion)
		if err != nil {
			return err
		}
		flavor := tmpl.DefaultFlavor
		if in.Flavor != "" {
			if flavor, err = s.flavorByName(ctx, tx, in.Flavor); err != nil {
				return err
			}
		}

		// Serialise admissions per project so concurrent requests cannot
		// both pass the quota check.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('cloud.project:' || $1, 0))`, in.ProjectID); err != nil {
			return fmt.Errorf("lock project: %w", err)
		}
		quota, usage, err := s.quotaAndUsage(ctx, tx, in.ProjectID)
		if err != nil {
			return err
		}
		if over := domain.QuotaViolations(quota, usage, flavor.Resources()); len(over) > 0 {
			return &domain.QuotaError{Exceeded: over, Quota: quota, Usage: usage}
		}

		network, err := s.lockNetwork(ctx, tx, in.NetworkID)
		if err != nil {
			return err
		}
		if network.ProjectID != in.ProjectID {
			return &domain.ValidationError{Field: "network_id", Code: "project", Message: "The network belongs to another project."}
		}
		if err := checkPlacement(ctx, tx, network, tmpl); err != nil {
			return err
		}
		ip, err := s.nextAddress(ctx, tx, network)
		if err != nil {
			return err
		}

		now := s.now()
		spec, err := json.Marshal(domain.WorkloadSpec{SSHAuthorizedKeys: in.SSHAuthorizedKeys, Env: in.Env})
		if err != nil {
			return fmt.Errorf("encode spec: %w", err)
		}
		id := s.opts.NewID()
		mac := ipam.RandomMAC()
		_, err = tx.Exec(ctx, `
			INSERT INTO cloud.workloads (id, project_id, name, kind, template_id, flavor_id, network_id,
			    vcpus, memory_mib, disk_gib, ip, mac, desired_state, state, spec, created_by,
			    created_at, updated_at, state_changed_at)
			VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5::text::uuid, $6::text::uuid, $7::text::uuid,
			    $8, $9, $10, $11::text::inet, $12::text::macaddr, 'running', 'PENDING', $13, $14, $15, $15, $15)`,
			id, in.ProjectID, in.Name, tmpl.Kind, tmpl.ID, flavor.ID, network.ID,
			flavor.VCPUs, flavor.MemoryMiB, flavor.DiskGiB, ip.String(), mac, spec, actor.ID, now)
		if err != nil {
			if code, constraint := pgCode(err); code == uniqueViolation && constraint == "workloads_live_name" {
				return domain.ErrNameTaken
			}
			return fmt.Errorf("insert workload: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO cloud.ip_allocations (network_id, ip, workload_id, mac)
			VALUES ($1::text::uuid, $2::text::inet, $3::text::uuid, $4::text::macaddr)`, network.ID, ip.String(), id, mac); err != nil {
			return fmt.Errorf("allocate address: %w", err)
		}

		created, err = s.lockWorkload(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := addEvent(ctx, tx, id, "created",
			fmt.Sprintf("created from template %s v%d, flavor %s, address %s", tmpl.Name, tmpl.Version, flavor.Name, ip), now); err != nil {
			return err
		}
		if err := emit(ctx, tx, ev(createdEvent(s.opts.Encoder, created))); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, auditRecord{
			Actor: actor, Action: "cloud.workloads.create", ResourceType: "workload", ResourceID: id, ProjectID: in.ProjectID,
			Details: map[string]string{
				"name": in.Name, "template": tmpl.Name + "@" + strconv.Itoa(tmpl.Version), "flavor": flavor.Name,
				"network_id": network.ID, "ip": ip.String(),
			},
		})
	})
	return created, err
}

func createdEvent(enc Encoder, w domain.Workload) (domain.OutboxEvent, error) {
	return enc.WorkloadCreated(w)
}

// checkPlacement enforces which workloads a network can carry.
func checkPlacement(ctx context.Context, tx pgx.Tx, n domain.Network, t domain.Template) error {
	if n.Kind == ipam.KindLab {
		if t.Kind == domain.KindContainer {
			return &domain.ValidationError{Field: "network_id", Code: "lab_requires_vm",
				Message: "Lab networks accept only virtual machines: containers share the host kernel."}
		}
		if !t.StaticNetwork {
			return &domain.ValidationError{Field: "template", Code: "lab_requires_static_network",
				Message: "Lab networks have no DHCP server; choose a template that configures a static address."}
		}
	}
	// A network is realised by one runtime on a host (a libvirt network for
	// VMs, a Docker network for containers), so it cannot mix kinds.
	var other string
	err := tx.QueryRow(ctx, `SELECT kind FROM cloud.workloads WHERE network_id = $1::text::uuid AND deleted_at IS NULL AND kind <> $2 LIMIT 1`,
		n.ID, t.Kind).Scan(&other)
	if err == nil {
		return &domain.ValidationError{Field: "network_id", Code: "mixed_kinds",
			Message: fmt.Sprintf("This network already carries %s workloads; use a separate network for %s workloads.", other, t.Kind)}
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("check network kinds: %w", err)
	}
	return nil
}

// nextAddress returns the lowest free address on a locked network.
func (s *Postgres) nextAddress(ctx context.Context, tx pgx.Tx, n domain.Network) (netip.Addr, error) {
	prefix, err := netip.ParsePrefix(n.CIDR)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("stored CIDR %q: %w", n.CIDR, err)
	}
	rows, err := tx.Query(ctx, `SELECT host(ip) FROM cloud.ip_allocations WHERE network_id = $1::text::uuid`, n.ID)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read allocations: %w", err)
	}
	used := map[netip.Addr]bool{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return netip.Addr{}, err
		}
		if a, err := netip.ParseAddr(raw); err == nil {
			used[a] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return netip.Addr{}, err
	}
	addr, err := ipam.NextFree(prefix, n.Kind, used)
	if errors.Is(err, ipam.ErrExhausted) {
		return netip.Addr{}, domain.ErrNetworkExhausted
	}
	return addr, err
}

// GetWorkload returns a workload, including a deleted one.
func (s *Postgres) GetWorkload(ctx context.Context, id string) (domain.Workload, error) {
	return scanWorkload(s.pool.QueryRow(ctx, workloadSelect+` WHERE w.id = $1::text::uuid`, id))
}

// ListWorkloads returns workloads matching f. Deleted workloads appear only
// when f.State is DELETED.
func (s *Postgres) ListWorkloads(ctx context.Context, f domain.WorkloadFilter) ([]domain.Workload, error) {
	rows, err := s.pool.Query(ctx, workloadSelect+`
		WHERE ($1 = '' OR w.project_id::text = $1)
		  AND ($2 = '' OR w.node_id::text = $2)
		  AND (CASE WHEN $3 = '' THEN w.deleted_at IS NULL ELSE w.state = $3 END)
		ORDER BY w.created_at DESC, w.id DESC
		LIMIT 500`, f.ProjectID, f.NodeID, f.State)
	if err != nil {
		return nil, fmt.Errorf("list workloads: %w", err)
	}
	return collectWorkloads(rows)
}

// WorkloadEvents returns a workload's history, newest first.
func (s *Postgres) WorkloadEvents(ctx context.Context, id string, limit int) ([]domain.WorkloadEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, ts, type, message FROM cloud.workload_events
		WHERE workload_id = $1::text::uuid ORDER BY id DESC LIMIT $2`, id, limit)
	if err != nil {
		return nil, fmt.Errorf("workload events: %w", err)
	}
	defer rows.Close()
	out := []domain.WorkloadEvent{}
	for rows.Next() {
		var e domain.WorkloadEvent
		if err := rows.Scan(&e.ID, &e.At, &e.Type, &e.Message); err != nil {
			return nil, fmt.Errorf("scan workload event: %w", err)
		}
		e.At = e.At.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// WorkloadMetrics returns a workload's samples since t, oldest first.
func (s *Postgres) WorkloadMetrics(ctx context.Context, id string, since time.Time) ([]domain.MetricPoint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ts, cpu_percent, memory_used_mib FROM cloud.workload_metrics
		WHERE workload_id = $1::text::uuid AND ts >= $2 ORDER BY ts`, id, since)
	if err != nil {
		return nil, fmt.Errorf("workload metrics: %w", err)
	}
	defer rows.Close()
	out := []domain.MetricPoint{}
	for rows.Next() {
		var p domain.MetricPoint
		var cpu float32
		if err := rows.Scan(&p.At, &cpu, &p.MemoryUsedMiB); err != nil {
			return nil, fmt.Errorf("scan workload metric: %w", err)
		}
		p.At, p.CPUPercent = p.At.UTC(), float64(cpu)
		out = append(out, p)
	}
	return out, rows.Err()
}

// ChangeDesiredState applies a start, stop, retry or delete request.
func (s *Postgres) ChangeDesiredState(ctx context.Context, id string, op domain.Operation, actor domain.Actor) (domain.Workload, error) {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		w, err := s.lockWorkload(ctx, tx, id)
		if err != nil {
			return err
		}
		if w.State == domain.StateDeleted {
			return domain.ErrInvalidState
		}
		now := s.now()
		// Every operation sets the new state; desired stays unless it changes.
		var state string
		desired, msg := w.DesiredState, ""
		switch op {
		case domain.OpStart:
			if !domain.CanStart(w) {
				return domain.ErrInvalidState
			}
			desired, state = domain.DesiredRunning, domain.StateProvisioning
		case domain.OpStop:
			if !domain.CanStop(w) {
				return domain.ErrInvalidState
			}
			desired, state = domain.DesiredStopped, domain.StateStopping
		case domain.OpRetry:
			if w.State != domain.StateError || w.DesiredState == domain.DesiredDeleted {
				return domain.ErrInvalidState
			}
			state = domain.StateScheduled
			if w.NodeID == "" {
				state = domain.StatePending
			}
		case domain.OpDelete:
			desired, state = domain.DesiredDeleted, domain.StateDeleting
			if w.NodeID == "" {
				// Never placed on a host: nothing to tear down.
				state = domain.StateDeleted
			}
		default:
			return fmt.Errorf("unknown operation %q", op)
		}

		if _, err := tx.Exec(ctx, `
			UPDATE cloud.workloads SET desired_state = $2, generation = generation + 1, updated_at = $3
			WHERE id = $1::text::uuid`, w.ID, desired, now); err != nil {
			return fmt.Errorf("update desired state: %w", err)
		}
		w.DesiredState = desired
		w.Generation++
		if err := addEvent(ctx, tx, w.ID, "request", fmt.Sprintf("%s requested by %s (generation %d)", op, actor.Name, w.Generation), now); err != nil {
			return err
		}
		observed := w.ObservedGeneration
		if state == domain.StateDeleted {
			observed = w.Generation
		}
		if err := s.setState(ctx, tx, w, state, msg, observed, now); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, auditRecord{
			Actor: actor, Action: "cloud.workloads." + string(op), ResourceType: "workload", ResourceID: w.ID,
			ProjectID: w.ProjectID, Details: map[string]string{"name": w.Name, "generation": strconv.FormatInt(w.Generation, 10)},
		})
	})
	if err != nil {
		return domain.Workload{}, err
	}
	return s.GetWorkload(ctx, id)
}

// PendingWorkloads returns the ids of workloads waiting for a node, oldest
// first.
func (s *Postgres) PendingWorkloads(ctx context.Context, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text FROM cloud.workloads WHERE state = 'PENDING' ORDER BY created_at, id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("pending workloads: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Schedule tries to bind one pending workload to a node. Every node row is
// locked while capacity is computed, so concurrent bindings cannot
// overcommit a node. It returns the scheduling result; an empty NodeID
// means the workload stays pending with the reason as its status message.
func (s *Postgres) Schedule(ctx context.Context, workloadID string) (scheduler.Result, error) {
	var result scheduler.Result
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		w, err := s.lockWorkload(ctx, tx, workloadID)
		if err != nil {
			return err
		}
		if w.State != domain.StatePending || w.DeletedAt != nil {
			return nil
		}
		rows, err := tx.Query(ctx, `SELECT `+nodeColumns+`, `+allocationColumns+` FROM cloud.nodes n`+allocationJoin+
			` ORDER BY n.id FOR UPDATE OF n`)
		if err != nil {
			return fmt.Errorf("lock nodes: %w", err)
		}
		var candidates []scheduler.Candidate
		for rows.Next() {
			n, err := scanNode(rows, true, s.opts.Overcommit)
			if err != nil {
				rows.Close()
				return err
			}
			candidates = append(candidates, scheduler.Candidate{Node: n, Allocated: n.Allocated})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		result = scheduler.Choose(candidates, scheduler.Request{Kind: w.Kind, Resources: w.Resources()}, s.opts.Overcommit)
		now := s.now()
		if result.NodeID == "" {
			return s.setState(ctx, tx, w, domain.StatePending, "unschedulable: "+result.Reason, w.ObservedGeneration, now)
		}
		if _, err := tx.Exec(ctx, `UPDATE cloud.workloads SET node_id = $2::text::uuid WHERE id = $1::text::uuid`,
			w.ID, result.NodeID); err != nil {
			return fmt.Errorf("bind workload: %w", err)
		}
		w.NodeID = result.NodeID
		for _, c := range candidates {
			if c.Node.ID == result.NodeID {
				w.NodeName = c.Node.Name
			}
		}
		return s.setState(ctx, tx, w, domain.StateScheduled, "placed on "+w.NodeName, w.ObservedGeneration, now)
	})
	return result, err
}
