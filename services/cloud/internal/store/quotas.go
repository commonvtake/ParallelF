package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
)

type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Postgres) quotaAndUsage(ctx context.Context, q querier, projectID string) (domain.Quota, domain.Usage, error) {
	quota := s.opts.DefaultQuota
	quota.ProjectID = projectID
	quota.IsDefault = true
	var updatedAt time.Time
	err := q.QueryRow(ctx, `
		SELECT max_vcpus, max_memory_mib, max_disk_gib, max_workloads, updated_by, updated_at
		FROM cloud.quotas WHERE project_id = $1::text::uuid`, projectID).
		Scan(&quota.MaxVCPUs, &quota.MaxMemoryMiB, &quota.MaxDiskGiB, &quota.MaxWorkloads, &quota.UpdatedBy, &updatedAt)
	switch {
	case err == nil:
		quota.IsDefault = false
		updatedAt = updatedAt.UTC()
		quota.UpdatedAt = &updatedAt
	case errors.Is(err, pgx.ErrNoRows):
	default:
		return domain.Quota{}, domain.Usage{}, fmt.Errorf("read quota: %w", err)
	}

	var usage domain.Usage
	err = q.QueryRow(ctx, `
		SELECT COALESCE(sum(vcpus), 0)::int, COALESCE(sum(memory_mib), 0)::int, COALESCE(sum(disk_gib), 0)::int, count(*)::int
		FROM cloud.workloads WHERE project_id = $1::text::uuid AND deleted_at IS NULL`, projectID).
		Scan(&usage.VCPUs, &usage.MemoryMiB, &usage.DiskGiB, &usage.Workloads)
	if err != nil {
		return domain.Quota{}, domain.Usage{}, fmt.Errorf("read usage: %w", err)
	}
	return quota, usage, nil
}

// GetQuota returns a project's quota (or the default) and its usage.
func (s *Postgres) GetQuota(ctx context.Context, projectID string) (domain.Quota, domain.Usage, error) {
	return s.quotaAndUsage(ctx, s.pool, projectID)
}

// PutQuota sets a project's quota.
func (s *Postgres) PutQuota(ctx context.Context, q domain.Quota, actor domain.Actor) (domain.Quota, error) {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO cloud.quotas (project_id, max_vcpus, max_memory_mib, max_disk_gib, max_workloads, updated_by, updated_at)
			VALUES ($1::text::uuid, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (project_id) DO UPDATE SET
			    max_vcpus = EXCLUDED.max_vcpus, max_memory_mib = EXCLUDED.max_memory_mib,
			    max_disk_gib = EXCLUDED.max_disk_gib, max_workloads = EXCLUDED.max_workloads,
			    updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
			q.ProjectID, q.MaxVCPUs, q.MaxMemoryMiB, q.MaxDiskGiB, q.MaxWorkloads, actor.ID, s.now())
		if err != nil {
			return fmt.Errorf("write quota: %w", err)
		}
		return s.appendAudit(ctx, tx, auditRecord{
			Actor: actor, Action: "cloud.quotas.update", ResourceType: "quota", ResourceID: q.ProjectID, ProjectID: q.ProjectID,
			Details: map[string]string{
				"max_vcpus": strconv.Itoa(q.MaxVCPUs), "max_memory_mib": strconv.Itoa(q.MaxMemoryMiB),
				"max_disk_gib": strconv.Itoa(q.MaxDiskGiB), "max_workloads": strconv.Itoa(q.MaxWorkloads),
			},
		})
	})
	if err != nil {
		return domain.Quota{}, err
	}
	quota, _, err := s.GetQuota(ctx, q.ProjectID)
	return quota, err
}
