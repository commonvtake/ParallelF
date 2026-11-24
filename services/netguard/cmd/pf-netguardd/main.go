// Command pf-netguardd is ParallelF NetGuard: it receives telemetry from
// network sensors, attributes addresses to Cloud workloads and VPN
// devices, runs detections, and serves alerts, incidents, evidence and
// signed discovery scopes.
package main

import (
	"context"
	"crypto/ed25519"
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
	"github.com/commonvtake/parallelf/services/netguard/internal/api"
	"github.com/commonvtake/parallelf/services/netguard/internal/app"
	ngconfig "github.com/commonvtake/parallelf/services/netguard/internal/config"
	"github.com/commonvtake/parallelf/services/netguard/internal/controller"
	"github.com/commonvtake/parallelf/services/netguard/internal/events"
	"github.com/commonvtake/parallelf/services/netguard/internal/sensorapi"
	"github.com/commonvtake/parallelf/services/netguard/internal/store"
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
	cfg, err := ngconfig.Load(config.FromEnv())
	if err != nil {
		return err
	}
	logger := logging.New(os.Stdout, logging.Options{Service: app.ServiceName, Version: version.Version, Level: cfg.LogLevel})
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DatabaseURL, store.Options{
		Encoder: events.NewEncoder(ids.NewV7, time.Now), NewID: ids.NewV7, Now: time.Now,
		Monitored: cfg.Monitored, ScopeKey: cfg.ScopeKey,
	})
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.EnsureInfrastructure(ctx, cfg.Infrastructure); err != nil {
		return err
	}

	pub, _ := cfg.ScopeKey.Public().(ed25519.PublicKey)
	ctrl := controller.New(db, controller.Options{Interval: time.Second, Retention: cfg.EventRetention}, logger)
	deps := app.Dependencies{
		Logger:      logger,
		Verifier:    oidcverifier.New(ctx, cfg.OIDC),
		API:         api.New(db, api.StepUp{MaxAuthAge: cfg.MaxAuthAge, ExemptClients: cfg.ExemptClients}, logger),
		SensorAPI:   sensorapi.New(db, cfg.JoinToken, pub, logger),
		ReadyChecks: map[string]httpx.Check{"postgres": db.Ping},
	}
	logger.Info("starting", slog.String("commit", version.Commit), slog.String("api_addr", cfg.HTTPAddr),
		slog.String("sensor_addr", cfg.SensorAddr), slog.Any("monitored", cfg.Monitored),
		slog.String("scope_key", sensorapi.Fingerprint(pub)), slog.Duration("event_retention", cfg.EventRetention),
		slog.Any("step_up_exempt_clients", cfg.ExemptClients))

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	serve := func(addr string, h http.Handler) {
		defer wg.Done()
		if err := httpx.Run(ctx, httpx.ServerOptions{Addr: addr, Handler: h, Logger: logger, ShutdownTimeout: cfg.ShutdownTimeout}); err != nil {
			errs <- err
			stop()
		}
	}
	wg.Add(3)
	go serve(cfg.HTTPAddr, app.NewAPIHandler(deps))
	go serve(cfg.SensorAddr, app.NewSensorHandler(deps))
	go func() { defer wg.Done(); ctrl.Run(ctx) }()
	wg.Wait()
	close(errs)
	var all []error
	for err := range errs {
		all = append(all, err)
	}
	return errors.Join(all...)
}
