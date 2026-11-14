// Command pf-cloudd is the ParallelF Cloud control plane: the workload API,
// the scheduler, and the endpoint node agents synchronise with.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/commonvtake/parallelf/pkg/authn/oidcverifier"
	"github.com/commonvtake/parallelf/pkg/config"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/ids"
	"github.com/commonvtake/parallelf/pkg/logging"
	"github.com/commonvtake/parallelf/pkg/version"
	"github.com/commonvtake/parallelf/services/cloud/internal/agentapi"
	"github.com/commonvtake/parallelf/services/cloud/internal/api"
	"github.com/commonvtake/parallelf/services/cloud/internal/app"
	cloudconfig "github.com/commonvtake/parallelf/services/cloud/internal/config"
	"github.com/commonvtake/parallelf/services/cloud/internal/controller"
	"github.com/commonvtake/parallelf/services/cloud/internal/coreclient"
	"github.com/commonvtake/parallelf/services/cloud/internal/events"
	"github.com/commonvtake/parallelf/services/cloud/internal/store"
)

func main() {
	healthcheck := flag.String("healthcheck", "", "probe the given URL and exit 0 when it answers 200 (container health check)")
	flag.Parse()

	if *healthcheck != "" {
		if err := httpx.Probe(context.Background(), *healthcheck); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		return
	}

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, app.ServiceName+":", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := cloudconfig.Load(config.FromEnv())
	if err != nil {
		return err
	}
	logger := logging.New(os.Stdout, logging.Options{Service: app.ServiceName, Version: version.Version, Level: cfg.LogLevel})
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DatabaseURL, store.Options{
		Encoder:      events.NewEncoder(ids.NewV7, time.Now),
		NewID:        ids.NewV7,
		Now:          time.Now,
		Overcommit:   cfg.Overcommit,
		DefaultQuota: cfg.DefaultQuota,
	})
	if err != nil {
		return err
	}
	defer db.Close()

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if err := db.Ping(pingCtx); err != nil {
		logger.Warn("database not reachable at startup", slog.String("error", err.Error()))
	}
	cancel()

	ctrl := controller.New(db, controller.Options{NodeTimeout: cfg.NodeTimeout, MetricsRetention: cfg.MetricsRetention}, logger)
	userAPI := api.New(db, coreclient.New(cfg.CoreURL, http.DefaultTransport), logger)
	userAPI.Scheduled = ctrl.Wake()
	deps := app.Dependencies{
		Logger:      logger,
		Verifier:    oidcverifier.New(ctx, cfg.OIDC),
		API:         userAPI,
		AgentAPI:    agentapi.New(db, cfg.JoinToken, logger),
		ReadyChecks: map[string]httpx.Check{"postgres": db.Ping},
	}

	logger.Info("starting",
		slog.String("commit", version.Commit),
		slog.String("api_addr", cfg.HTTPAddr),
		slog.String("agent_addr", cfg.AgentAddr),
		slog.Float64("cpu_overcommit", cfg.Overcommit.CPU),
		slog.Duration("node_timeout", cfg.NodeTimeout),
	)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	serve := func(addr string, h http.Handler) {
		defer wg.Done()
		if err := httpx.Run(ctx, httpx.ServerOptions{Addr: addr, Handler: h, Logger: logger, ShutdownTimeout: cfg.ShutdownTimeout}); err != nil {
			errs <- err
			stop() // one server failing takes the process down
		}
	}
	wg.Add(3)
	go serve(cfg.HTTPAddr, app.NewAPIHandler(deps))
	go serve(cfg.AgentAddr, app.NewAgentHandler(deps))
	go func() { defer wg.Done(); ctrl.Run(ctx) }()
	wg.Wait()

	close(errs)
	var all []error
	for err := range errs {
		all = append(all, err)
	}
	return errors.Join(all...)
}
