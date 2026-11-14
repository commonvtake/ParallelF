package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
)

// Sync records a node's report and returns its complete desired state, in
// one transaction:
//
//  1. the node is marked READY and its capacity and metrics are stored;
//  2. every observation is applied to its workload (domain.Observe), with
//     history, outbox events and metrics;
//  3. the workloads still assigned to the node are returned with their
//     templates and networks.
func (s *Postgres) Sync(ctx context.Context, node domain.Node, req cloudagent.SyncRequest) (domain.HostDesiredState, error) {
	var desired domain.HostDesiredState
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		now := s.now()

		var previous string
		if err := tx.QueryRow(ctx, `SELECT status FROM cloud.nodes WHERE id = $1::text::uuid FOR UPDATE`, node.ID).Scan(&previous); err != nil {
			return fmt.Errorf("lock node: %w", err)
		}
		info := req.Node
		_, err := tx.Exec(ctx, `
			UPDATE cloud.nodes SET status = 'READY', last_seen_at = $2, agent_version = $3, kvm = $4, docker = $5,
			    hypervisor = $6, cpu_count = $7, memory_mib = $8, disk_gib = $9, reserved_cpus = $10,
			    reserved_memory_mib = $11, reserved_disk_gib = $12
			WHERE id = $1::text::uuid`,
			node.ID, now, req.AgentVersion, info.KVM, info.Docker, info.Hypervisor, info.CPUCount, info.MemoryMiB,
			info.DiskGiB, info.ReservedCPUs, info.ReservedMemoryMiB, info.ReservedDiskGiB)
		if err != nil {
			return fmt.Errorf("update node: %w", err)
		}
		if previous != domain.NodeReady {
			node.Status = domain.NodeReady
			if err := emit(ctx, tx, ev(nodeStatusEvent(s.opts.Encoder, node, previous, domain.NodeReady, now))); err != nil {
				return err
			}
		}
		if m := req.Metrics; m != nil {
			_, err := tx.Exec(ctx, `
				INSERT INTO cloud.node_metrics (node_id, ts, cpu_percent, memory_used_mib, memory_total_mib, disk_used_gib, disk_total_gib)
				VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING`,
				node.ID, now, m.CPUPercent, m.MemoryUsedMiB, m.MemoryTotalMiB, m.DiskUsedGiB, m.DiskTotalGiB)
			if err != nil {
				return fmt.Errorf("insert node metrics: %w", err)
			}
		}

		observed := make(map[string]*cloudagent.ObservedWorkload, len(req.Workloads))
		for i := range req.Workloads {
			observed[req.Workloads[i].ID] = &req.Workloads[i]
		}

		workloads, err := s.lockWorkloads(ctx, tx, `w.node_id = $1::text::uuid AND w.deleted_at IS NULL`, node.ID)
		if err != nil {
			return err
		}
		live := workloads[:0]
		for _, w := range workloads {
			obs := observed[w.ID]
			t := domain.Observe(w, obs)
			if t.Changed(w) {
				if err := s.setState(ctx, tx, w, t.State, t.Message, t.ObservedGeneration, now); err != nil {
					return err
				}
				w.State, w.StatusMessage, w.ObservedGeneration = t.State, t.Message, t.ObservedGeneration
			}
			if obs != nil && obs.CPUPercent != nil && obs.MemoryUsedMiB != nil && w.State == domain.StateRunning {
				_, err := tx.Exec(ctx, `
					INSERT INTO cloud.workload_metrics (workload_id, ts, cpu_percent, memory_used_mib)
					VALUES ($1::text::uuid, $2, $3, $4) ON CONFLICT DO NOTHING`,
					w.ID, now, *obs.CPUPercent, *obs.MemoryUsedMiB)
				if err != nil {
					return fmt.Errorf("insert workload metrics: %w", err)
				}
			}
			if w.State != domain.StateDeleted {
				live = append(live, w)
			}
		}

		templateIDs := make([]string, 0, len(live))
		networkIDs := map[string]bool{}
		for _, w := range live {
			templateIDs = append(templateIDs, w.TemplateID)
			networkIDs[w.NetworkID] = true
		}
		templates, err := s.templatesByID(ctx, tx, templateIDs)
		if err != nil {
			return err
		}
		networks := make(map[string]domain.Network, len(networkIDs))
		for id := range networkIDs {
			// Workloads keep their network until they are deleted, so the
			// network row is live; GetNetwork-style read inside the tx.
			n, err := scanNetwork(tx.QueryRow(ctx, networkSelect+` WHERE n.id = $1::text::uuid`, id))
			if err != nil {
				return err
			}
			networks[id] = n
		}
		for _, w := range live {
			desired.Workloads = append(desired.Workloads, domain.DesiredWorkload{
				Workload: w, Template: templates[w.TemplateID], Network: networks[w.NetworkID],
			})
			if w.Converging() {
				desired.Converging = true
			}
		}
		return nil
	})
	return desired, err
}
