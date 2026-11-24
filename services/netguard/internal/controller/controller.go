// Package controller runs pf-netguardd's background work: detection over
// new telemetry, attribution from Cloud and VPN events, and retention.
package controller

import (
	"context"
	"log/slog"
	"time"

	"github.com/commonvtake/parallelf/services/netguard/internal/store"
)

// Store is what the controller drives.
type Store interface {
	Detect(ctx context.Context) (store.DetectResult, error)
	Consume(ctx context.Context, source string) (store.ConsumeResult, error)
	PruneEvents(ctx context.Context, before time.Time) (int64, error)
}

// Options tune the loops.
type Options struct {
	Interval  time.Duration
	Retention time.Duration
}

// Controller runs the loops.
type Controller struct {
	store  Store
	opts   Options
	logger *slog.Logger
	failed map[string]bool
}

// New returns a controller.
func New(s Store, opts Options, logger *slog.Logger) *Controller {
	if opts.Interval == 0 {
		opts.Interval = time.Second
	}
	return &Controller{store: s, opts: opts, logger: logger, failed: map[string]bool{}}
}

// report logs a failure once per streak, and the recovery.
func (c *Controller) report(step string, err error) {
	switch {
	case err != nil && !c.failed[step]:
		c.failed[step] = true
		c.logger.Error(step+" failed", slog.String("error", err.Error()))
	case err == nil && c.failed[step]:
		c.failed[step] = false
		c.logger.Info(step + " recovered")
	}
}

// Step runs one round: attribution first, so detection sees the newest
// owners of addresses; detection until it has caught up.
func (c *Controller) Step(ctx context.Context) {
	for _, source := range []string{"cloud", "vpn"} {
		res, err := c.store.Consume(ctx, source)
		c.report("consume "+source, err)
		if res.Applied > 0 {
			c.logger.Info("attribution updated", slog.String("source", source), slog.Int("applied", res.Applied))
		}
	}
	for range 20 {
		res, err := c.store.Detect(ctx)
		c.report("detect", err)
		if err != nil || res.Events == 0 {
			return
		}
		if res.Raised > 0 {
			c.logger.Info("alerts raised", slog.Int("events", res.Events), slog.Int("findings", res.Findings), slog.Int("raised", res.Raised))
		}
		if res.Events < store.DetectBatch {
			return
		}
	}
}

// Run loops until ctx ends.
func (c *Controller) Run(ctx context.Context) {
	tick := time.NewTicker(c.opts.Interval)
	defer tick.Stop()
	lastPrune := time.Time{}
	for {
		c.Step(ctx)
		if time.Since(lastPrune) > time.Hour {
			n, err := c.store.PruneEvents(ctx, time.Now().Add(-c.opts.Retention))
			c.report("prune", err)
			if n > 0 {
				c.logger.Info("telemetry pruned", slog.Int64("events", n))
			}
			lastPrune = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
