package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
	"github.com/commonvtake/parallelf/services/cloud/internal/ipam"
)

const networkSelect = `
	SELECT n.id::text, n.project_id::text, n.name, n.kind, n.cidr::text, COALESCE(host(n.gateway_ip), ''),
	       n.bridge_name, n.created_by, n.created_at, n.deleted_at,
	       (SELECT count(*)::int FROM cloud.workloads w WHERE w.network_id = n.id AND w.deleted_at IS NULL)
	FROM cloud.networks n`

func scanNetwork(row pgx.Row) (domain.Network, error) {
	var n domain.Network
	err := row.Scan(&n.ID, &n.ProjectID, &n.Name, &n.Kind, &n.CIDR, &n.GatewayIP, &n.BridgeName,
		&n.CreatedBy, &n.CreatedAt, &n.DeletedAt, &n.Workloads)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Network{}, domain.ErrNotFound
		}
		return domain.Network{}, fmt.Errorf("scan network: %w", err)
	}
	n.CreatedAt = n.CreatedAt.UTC()
	if p, err := netip.ParsePrefix(n.CIDR); err == nil {
		n.Capacity = ipam.Capacity(p, n.Kind)
	}
	return n, nil
}

// CreateNetwork records a network. Overlapping live CIDRs are rejected by
// the database's exclusion constraint.
func (s *Postgres) CreateNetwork(ctx context.Context, in domain.NetworkInput, actor domain.Actor) (domain.Network, error) {
	prefix, err := ipam.ValidateCIDR(in.CIDR)
	if err != nil {
		return domain.Network{}, &domain.ValidationError{Field: "cidr", Code: "format", Message: "CIDR " + err.Error() + "."}
	}
	var created domain.Network
	err = s.inTx(ctx, func(tx pgx.Tx) error {
		id := s.opts.NewID()
		var gateway any
		if gw, ok := ipam.Gateway(prefix, in.Kind); ok {
			gateway = gw.String()
		}
		now := s.now()
		_, err := tx.Exec(ctx, `
			INSERT INTO cloud.networks (id, project_id, name, kind, cidr, gateway_ip, bridge_name, created_by, created_at)
			VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5::text::cidr, $6::text::inet, $7, $8, $9)`,
			id, in.ProjectID, in.Name, in.Kind, prefix.String(), gateway, ipam.BridgeName(id), actor.ID, now)
		if err != nil {
			switch code, constraint := pgCode(err); {
			case code == exclusionViolation:
				return domain.ErrCIDROverlap
			case code == uniqueViolation && constraint == "networks_live_name":
				return domain.ErrNameTaken
			}
			return fmt.Errorf("insert network: %w", err)
		}
		created, err = scanNetwork(tx.QueryRow(ctx, networkSelect+` WHERE n.id = $1::text::uuid`, id))
		if err != nil {
			return err
		}
		if err := emit(ctx, tx, ev(s.opts.Encoder.NetworkCreated(created))); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, auditRecord{
			Actor: actor, Action: "cloud.networks.create", ResourceType: "network", ResourceID: id, ProjectID: in.ProjectID,
			Details: map[string]string{"name": in.Name, "kind": in.Kind, "cidr": prefix.String()},
		})
	})
	return created, err
}

// lockLiveNetwork locks a live network row and then reads it, with its
// workload count, in a new statement: a count read by the locking statement
// itself would come from the snapshot taken before waiting for the lock, and
// miss workloads a concurrent transaction just added.
func (s *Postgres) lockLiveNetwork(ctx context.Context, tx pgx.Tx, id string) (domain.Network, error) {
	tag, err := tx.Exec(ctx, `SELECT 1 FROM cloud.networks WHERE id = $1::text::uuid AND deleted_at IS NULL FOR UPDATE`, id)
	if err != nil {
		return domain.Network{}, fmt.Errorf("lock network: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return domain.Network{}, domain.ErrNotFound
	}
	return scanNetwork(tx.QueryRow(ctx, networkSelect+` WHERE n.id = $1::text::uuid`, id))
}

// lockNetwork locks a live network for admitting a workload to it.
func (s *Postgres) lockNetwork(ctx context.Context, tx pgx.Tx, id string) (domain.Network, error) {
	n, err := s.lockLiveNetwork(ctx, tx, id)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.Network{}, &domain.ValidationError{Field: "network_id", Code: "not_found", Message: "No network has this id."}
	}
	return n, err
}

// GetNetwork returns a network, including a deleted one.
func (s *Postgres) GetNetwork(ctx context.Context, id string) (domain.Network, error) {
	return scanNetwork(s.pool.QueryRow(ctx, networkSelect+` WHERE n.id = $1::text::uuid`, id))
}

// ListNetworks returns live networks, optionally of one project.
func (s *Postgres) ListNetworks(ctx context.Context, projectID string) ([]domain.Network, error) {
	rows, err := s.pool.Query(ctx, networkSelect+`
		WHERE n.deleted_at IS NULL AND ($1 = '' OR n.project_id::text = $1)
		ORDER BY n.created_at, n.id`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list networks: %w", err)
	}
	defer rows.Close()
	out := []domain.Network{}
	for rows.Next() {
		n, err := scanNetwork(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// DeleteNetwork removes a network that no live workload uses. Hosts remove
// the bridge on their next sync, because it is no longer desired.
func (s *Postgres) DeleteNetwork(ctx context.Context, id string, actor domain.Actor) error {
	return s.inTx(ctx, func(tx pgx.Tx) error {
		n, err := s.lockLiveNetwork(ctx, tx, id)
		if err != nil {
			return err
		}
		if n.Workloads > 0 {
			return domain.ErrNetworkInUse
		}
		now := s.now()
		if _, err := tx.Exec(ctx, `UPDATE cloud.networks SET deleted_at = $2 WHERE id = $1::text::uuid`, id, now); err != nil {
			return fmt.Errorf("delete network: %w", err)
		}
		if err := emit(ctx, tx, ev(s.opts.Encoder.NetworkDeleted(n, actor.ID, now))); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, auditRecord{
			Actor: actor, Action: "cloud.networks.delete", ResourceType: "network", ResourceID: id, ProjectID: n.ProjectID,
			Details: map[string]string{"name": n.Name, "cidr": n.CIDR},
		})
	})
}
