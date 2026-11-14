// Package controller runs pf-cloudd's background loops: placing pending
// workloads, detecting nodes that stopped reporting, and pruning old
// metrics. Every loop is level-triggered: it reads the current state from
// the store on each pass, so a restart of pf-cloudd loses nothing.
package controller

import (
	"context"
	"log/slog"
	"time"

	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
	"github.com/commonvtake/parallelf/services/cloud/internal/scheduler"
)

// Store is the persistence the controller needs.
type Store interface {
	PendingWorkloads(ctx context.Context, limit int) ([]string, error)
	Schedule(ctx context.Context, workloadID string) (scheduler.Result, error)
	MarkUnresponsiveNodes(ctx context.Context, deadline time.Time) ([]domain.Node, error)
	DeleteMetricsBefore(ctx context.Context, t time.Time) (int64, error)
}

// Options configures the loops.
type Options struct {
	// NodeTimeout is how long a node may go without syncing before it is
	// NOT_READY and its workloads UNKNOWN.
	NodeTimeout time.Duration
	// MetricsRetention is how long utilisation samples are kept.
	MetricsRetention time.Duration
	// SchedulePeriod is the interval of the scheduler's sweep.
	SchedulePeriod time.Duration
	// MonitorPeriod is the interval of the node-health check.
	MonitorPeriod time.Duration
}

// Controller owns the loops.
type Controller struct {
	store  Store
	opts   Options
	logger *slog.Logger
	now    func() time.Time
	wake   chan struct{}
}

// New returns a Controller.
func New(s Store, opts Options, logger *slog.Logger) *Controller {
	if opts.SchedulePeriod <= 0 {
		opts.SchedulePeriod = 5 * time.Second
	}
	if opts.MonitorPeriod <= 0 {
		opts.MonitorPeriod = 5 * time.Second
	}
	return &Controller{store: s, opts: opts, logger: logger, now: time.Now, wake: make(chan struct{}, 1)}
}

// Wake returns the channel that triggers an immediate scheduling pass.
func (c *Controller) Wake() chan<- struct{} { return c.wake }

// Run blocks until ctx is cancelled.
func (c *Controller) Run(ctx context.Context) {
	schedule := time.NewTicker(c.opts.SchedulePeriod)
	monitor := time.NewTicker(c.opts.MonitorPeriod)
	prune := time.NewTicker(10 * time.Minute)
	defer schedule.Stop()
	defer monitor.Stop()
	defer prune.Stop()

	c.SchedulePass(ctx)
	c.MonitorPass(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.wake:
			c.SchedulePass(ctx)
		case <-schedule.C:
			c.SchedulePass(ctx)
		case <-monitor.C:
			c.MonitorPass(ctx)
		case <-prune.C:
			c.PrunePass(ctx)
		}
	}
}

// SchedulePass tries to place every pending workload, oldest first.
func (c *Controller) SchedulePass(ctx context.Context) {
	pending, err := c.store.PendingWorkloads(ctx, 100)
	if err != nil {
		c.logger.ErrorContext(ctx, "list pending workloads", slog.String("error", err.Error()))
		return
	}
	for _, id := range pending {
		result, err := c.store.Schedule(ctx, id)
		if err != nil {
			c.logger.ErrorContext(ctx, "schedule workload", slog.String("workload_id", id), slog.String("error", err.Error()))
			continue
		}
		if result.NodeID != "" {
			c.logger.InfoContext(ctx, "workload scheduled", slog.String("workload_id", id), slog.String("node_id", result.NodeID))
		}
	}
}

// MonitorPass marks nodes that stopped reporting.
func (c *Controller) MonitorPass(ctx context.Context) {
	nodes, err := c.store.MarkUnresponsiveNodes(ctx, c.now().Add(-c.opts.NodeTimeout))
	if err != nil {
		c.logger.ErrorContext(ctx, "check node health", slog.String("error", err.Error()))
		return
	}
	for _, n := range nodes {
		c.logger.WarnContext(ctx, "node stopped reporting", slog.String("node_id", n.ID), slog.String("name", n.Name))
	}
}

// PrunePass deletes metric samples past their retention.
func (c *Controller) PrunePass(ctx context.Context) {
	n, err := c.store.DeleteMetricsBefore(ctx, c.now().Add(-c.opts.MetricsRetention))
	if err != nil {
		c.logger.ErrorContext(ctx, "prune metrics", slog.String("error", err.Error()))
		return
	}
	if n > 0 {
		c.logger.Info("pruned metrics", slog.Int64("rows", n))
	}
}
