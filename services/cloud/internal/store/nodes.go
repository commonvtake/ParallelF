package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
)

const nodeColumns = `n.id::text, n.name, n.status, n.schedulable, n.agent_version, n.kvm, n.docker, n.hypervisor,
	n.cpu_count, n.memory_mib, n.disk_gib, n.reserved_cpus, n.reserved_memory_mib, n.reserved_disk_gib,
	n.registered_at, n.last_seen_at`

// allocationJoin adds the resources reserved by live workloads on each node.
const allocationJoin = `
	LEFT JOIN (
		SELECT node_id, sum(vcpus)::int AS vcpus, sum(memory_mib)::bigint AS mem, sum(disk_gib)::bigint AS disk,
		       count(*)::int AS workloads
		FROM cloud.workloads WHERE deleted_at IS NULL AND node_id IS NOT NULL
		GROUP BY node_id
	) a ON a.node_id = n.id`

const allocationColumns = `COALESCE(a.vcpus, 0), COALESCE(a.mem, 0), COALESCE(a.disk, 0), COALESCE(a.workloads, 0)`

func scanNode(row pgx.Row, withAllocation bool, oc domain.Overcommit) (domain.Node, error) {
	var n domain.Node
	dest := []any{&n.ID, &n.Name, &n.Status, &n.Schedulable, &n.AgentVersion, &n.KVM, &n.Docker, &n.Hypervisor,
		&n.CPUCount, &n.MemoryMiB, &n.DiskGiB, &n.ReservedCPUs, &n.ReservedMemoryMiB, &n.ReservedDiskGiB,
		&n.RegisteredAt, &n.LastSeenAt}
	if withAllocation {
		dest = append(dest, &n.Allocated.VCPUs, &n.Allocated.MemoryMiB, &n.Allocated.DiskGiB, &n.Workloads)
	}
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Node{}, domain.ErrNotFound
		}
		return domain.Node{}, fmt.Errorf("scan node: %w", err)
	}
	n.RegisteredAt = n.RegisteredAt.UTC()
	n.LastSeenAt = n.LastSeenAt.UTC()
	n.Allocatable = n.AllocatableResources(oc)
	return n, nil
}

// RegisterNode adds a node, or gives an existing node of the same name a
// new credential (re-installing an agent must not orphan its workloads).
func (s *Postgres) RegisterNode(ctx context.Context, r domain.NodeRegistration, actor domain.Actor) (domain.Node, error) {
	var node domain.Node
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		now := s.now()
		row := tx.QueryRow(ctx, `
			INSERT INTO cloud.nodes AS n (id, name, status, token_hash, agent_version, kvm, docker, hypervisor,
			    cpu_count, memory_mib, disk_gib, reserved_cpus, reserved_memory_mib, reserved_disk_gib,
			    registered_at, last_seen_at)
			VALUES ($1::text::uuid, $2, 'READY', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)
			ON CONFLICT (name) DO UPDATE SET
			    status = 'READY', token_hash = EXCLUDED.token_hash, agent_version = EXCLUDED.agent_version,
			    kvm = EXCLUDED.kvm, docker = EXCLUDED.docker, hypervisor = EXCLUDED.hypervisor,
			    cpu_count = EXCLUDED.cpu_count, memory_mib = EXCLUDED.memory_mib, disk_gib = EXCLUDED.disk_gib,
			    reserved_cpus = EXCLUDED.reserved_cpus, reserved_memory_mib = EXCLUDED.reserved_memory_mib,
			    reserved_disk_gib = EXCLUDED.reserved_disk_gib, registered_at = EXCLUDED.registered_at,
			    last_seen_at = EXCLUDED.last_seen_at
			RETURNING `+nodeColumns,
			s.opts.NewID(), r.Name, r.TokenHash, r.AgentVersion, r.KVM, r.Docker, r.Hypervisor,
			r.CPUCount, r.MemoryMiB, r.DiskGiB, r.ReservedCPUs, r.ReservedMiB, r.ReservedGiB, now)
		var err error
		node, err = scanNode(row, false, s.opts.Overcommit)
		if err != nil {
			return fmt.Errorf("register node: %w", err)
		}
		if err := emit(ctx, tx, ev(encodeNode(s.opts.Encoder, node))); err != nil {
			return err
		}
		actor.ID, actor.Name = node.ID, node.Name
		return s.appendAudit(ctx, tx, auditRecord{
			Actor: actor, Action: "cloud.nodes.register", ResourceType: "node", ResourceID: node.ID,
			Details: map[string]string{"name": node.Name, "agent_version": node.AgentVersion},
		})
	})
	return node, err
}

func encodeNode(enc Encoder, n domain.Node) (domain.OutboxEvent, error) { return enc.NodeRegistered(n) }

// AuthenticateNode returns the node owning the credential hash.
func (s *Postgres) AuthenticateNode(ctx context.Context, tokenHash []byte) (domain.Node, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+nodeColumns+` FROM cloud.nodes n WHERE n.token_hash = $1`, tokenHash)
	n, err := scanNode(row, false, s.opts.Overcommit)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.Node{}, domain.ErrUnauthorizedNode
	}
	return n, err
}

// ListNodes returns every node with its current allocation.
func (s *Postgres) ListNodes(ctx context.Context) ([]domain.Node, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+nodeColumns+`, `+allocationColumns+` FROM cloud.nodes n`+allocationJoin+` ORDER BY n.name`)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	defer rows.Close()
	var out []domain.Node
	for rows.Next() {
		n, err := scanNode(rows, true, s.opts.Overcommit)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// GetNode returns one node with its current allocation.
func (s *Postgres) GetNode(ctx context.Context, id string) (domain.Node, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+nodeColumns+`, `+allocationColumns+` FROM cloud.nodes n`+allocationJoin+
		` WHERE n.id = $1::text::uuid`, id)
	return scanNode(row, true, s.opts.Overcommit)
}

// SetNodeSchedulable cordons (false) or uncordons (true) a node.
func (s *Postgres) SetNodeSchedulable(ctx context.Context, id string, schedulable bool, actor domain.Actor) (domain.Node, error) {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		var name string
		err := tx.QueryRow(ctx, `UPDATE cloud.nodes SET schedulable = $2 WHERE id = $1::text::uuid RETURNING name`,
			id, schedulable).Scan(&name)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("update node: %w", err)
		}
		action := "cloud.nodes.cordon"
		if schedulable {
			action = "cloud.nodes.uncordon"
		}
		return s.appendAudit(ctx, tx, auditRecord{Actor: actor, Action: action, ResourceType: "node", ResourceID: id,
			Details: map[string]string{"name": name}})
	})
	if err != nil {
		return domain.Node{}, err
	}
	return s.GetNode(ctx, id)
}

// DeleteNode removes a node that has stopped reporting and holds no live
// workloads.
func (s *Postgres) DeleteNode(ctx context.Context, id string, actor domain.Actor) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		var name, status string
		err := tx.QueryRow(ctx, `SELECT name, status FROM cloud.nodes WHERE id = $1::text::uuid FOR UPDATE`, id).Scan(&name, &status)
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lock node: %w", err)
		}
		if status == domain.NodeReady {
			return domain.ErrNodeActive
		}
		var live int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM cloud.workloads WHERE node_id = $1::text::uuid AND deleted_at IS NULL`,
			id).Scan(&live); err != nil {
			return fmt.Errorf("count workloads: %w", err)
		}
		if live > 0 {
			return domain.ErrInvalidState
		}
		// Deleted workloads keep their history but no longer point at the node.
		if _, err := tx.Exec(ctx, `UPDATE cloud.workloads SET node_id = NULL WHERE node_id = $1::text::uuid`, id); err != nil {
			return fmt.Errorf("detach history: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM cloud.nodes WHERE id = $1::text::uuid`, id); err != nil {
			return fmt.Errorf("delete node: %w", err)
		}
		return s.appendAudit(ctx, tx, auditRecord{Actor: actor, Action: "cloud.nodes.delete", ResourceType: "node",
			ResourceID: id, Details: map[string]string{"name": name}})
	})
}

// MarkUnresponsiveNodes sets nodes whose last report is older than
// deadline to NOT_READY, and their active workloads to UNKNOWN.
func (s *Postgres) MarkUnresponsiveNodes(ctx context.Context, deadline time.Time) ([]domain.Node, error) {
	var changed []domain.Node
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT `+nodeColumns+` FROM cloud.nodes n
			WHERE n.status = 'READY' AND n.last_seen_at < $1
			ORDER BY n.id FOR UPDATE`, deadline)
		if err != nil {
			return fmt.Errorf("find unresponsive nodes: %w", err)
		}
		for rows.Next() {
			n, err := scanNode(rows, false, s.opts.Overcommit)
			if err != nil {
				rows.Close()
				return err
			}
			changed = append(changed, n)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		now := s.now()
		for i := range changed {
			n := &changed[i]
			if _, err := tx.Exec(ctx, `UPDATE cloud.nodes SET status = 'NOT_READY' WHERE id = $1::text::uuid`, n.ID); err != nil {
				return fmt.Errorf("mark node: %w", err)
			}
			n.Status = domain.NodeNotReady
			if err := emit(ctx, tx, ev(nodeStatusEvent(s.opts.Encoder, *n, domain.NodeReady, domain.NodeNotReady, now))); err != nil {
				return err
			}
			workloads, err := s.lockWorkloads(ctx, tx, `w.node_id = $1::text::uuid AND w.deleted_at IS NULL
				AND w.state IN ('RUNNING', 'PROVISIONING', 'STOPPING')`, n.ID)
			if err != nil {
				return err
			}
			for _, w := range workloads {
				msg := fmt.Sprintf("node %s stopped reporting", n.Name)
				if err := s.setState(ctx, tx, w, domain.StateUnknown, msg, w.ObservedGeneration, now); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return changed, err
}

func nodeStatusEvent(enc Encoder, n domain.Node, from, to string, at time.Time) (domain.OutboxEvent, error) {
	return enc.NodeStatusChanged(n, from, to, at)
}

// NodeMetrics returns a node's samples since the given time, oldest first.
func (s *Postgres) NodeMetrics(ctx context.Context, nodeID string, since time.Time) ([]domain.MetricPoint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ts, cpu_percent, memory_used_mib, memory_total_mib, disk_used_gib, disk_total_gib
		FROM cloud.node_metrics WHERE node_id = $1::text::uuid AND ts >= $2 ORDER BY ts`, nodeID, since)
	if err != nil {
		return nil, fmt.Errorf("node metrics: %w", err)
	}
	defer rows.Close()
	out := []domain.MetricPoint{}
	for rows.Next() {
		var p domain.MetricPoint
		var cpu, diskUsed, diskTotal float32
		if err := rows.Scan(&p.At, &cpu, &p.MemoryUsedMiB, &p.MemoryTotalMiB, &diskUsed, &diskTotal); err != nil {
			return nil, fmt.Errorf("scan node metric: %w", err)
		}
		p.At, p.CPUPercent, p.DiskUsedGiB, p.DiskTotalGiB = p.At.UTC(), float64(cpu), float64(diskUsed), float64(diskTotal)
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteMetricsBefore removes samples older than t from both metric tables.
func (s *Postgres) DeleteMetricsBefore(ctx context.Context, t time.Time) (int64, error) {
	a, err := s.pool.Exec(ctx, `DELETE FROM cloud.node_metrics WHERE ts < $1`, t)
	if err != nil {
		return 0, fmt.Errorf("prune node metrics: %w", err)
	}
	b, err := s.pool.Exec(ctx, `DELETE FROM cloud.workload_metrics WHERE ts < $1`, t)
	if err != nil {
		return 0, fmt.Errorf("prune workload metrics: %w", err)
	}
	return a.RowsAffected() + b.RowsAffected(), nil
}
