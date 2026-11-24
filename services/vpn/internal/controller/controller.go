// Package controller runs pf-vpnd's periodic work: marking silent gateways,
// expiring devices and pruning old traffic samples.
package controller

import (
	"context"
	"log/slog"
	"time"

	"github.com/commonvtake/parallelf/services/vpn/internal/domain"
)

// Store is what the controller needs.
type Store interface {
	MarkSilentGateways(ctx context.Context, deadline time.Time) ([]domain.Gateway, error)
	ExpireDevices(ctx context.Context, now time.Time) (int, error)
	PruneStats(ctx context.Context, before time.Time) (int64, error)
}

// Options tune the controller.
type Options struct {
	GatewayTimeout time.Duration
	StatsRetention time.Duration
	Period         time.Duration
}

// Controller runs the passes.
type Controller struct {
	store  Store
	opts   Options
	logger *slog.Logger
	now    func() time.Time
}

// New returns a controller.
func New(s Store, opts Options, logger *slog.Logger) *Controller {
	if opts.Period <= 0 {
		opts.Period = 5 * time.Second
	}
	return &Controller{store: s, opts: opts, logger: logger, now: time.Now}
}

// Pass runs every check once.
func (c *Controller) Pass(ctx context.Context) {
	now := c.now()
	if changed, err := c.store.MarkSilentGateways(ctx, now.Add(-c.opts.GatewayTimeout)); err != nil {
		c.logger.Error("gateway liveness", slog.String("error", err.Error()))
	} else {
		for _, g := range changed {
			c.logger.Warn("gateway stopped reporting; activations keep expiring in its kernel",
				slog.String("gateway", g.Name), slog.String("gateway_id", g.ID))
		}
	}
	if n, err := c.store.ExpireDevices(ctx, now); err != nil {
		c.logger.Error("device expiry", slog.String("error", err.Error()))
	} else if n > 0 {
		c.logger.Info("devices expired", slog.Int("count", n))
	}
}

// Prune deletes old traffic samples.
func (c *Controller) Prune(ctx context.Context) {
	if n, err := c.store.PruneStats(ctx, c.now().Add(-c.opts.StatsRetention)); err != nil {
		c.logger.Error("prune stats", slog.String("error", err.Error()))
	} else if n > 0 {
		c.logger.Debug("pruned peer statistics", slog.Int64("rows", n))
	}
}

// Run loops until ctx ends.
func (c *Controller) Run(ctx context.Context) {
	tick := time.NewTicker(c.opts.Period)
	prune := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	defer prune.Stop()
	c.Pass(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			c.Pass(ctx)
		case <-prune.C:
			c.Prune(ctx)
		}
	}
}
