// Command pf-core is the ParallelF platform core service: the authenticated
// caller's profile and projects, backed by PostgreSQL.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/commonvtake/parallelf/pkg/authn/oidcverifier"
	"github.com/commonvtake/parallelf/pkg/config"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/ids"
	"github.com/commonvtake/parallelf/pkg/logging"
	"github.com/commonvtake/parallelf/pkg/version"
	"github.com/commonvtake/parallelf/services/core/internal/app"
	coreconfig "github.com/commonvtake/parallelf/services/core/internal/config"
	"github.com/commonvtake/parallelf/services/core/internal/events"
	"github.com/commonvtake/parallelf/services/core/internal/projects"
	"github.com/commonvtake/parallelf/services/core/internal/store"
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
	cfg, err := coreconfig.Load(config.FromEnv())
	if err != nil {
		return err
	}
	logger := logging.New(os.Stdout, logging.Options{Service: app.ServiceName, Version: version.Version, Level: cfg.LogLevel})
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer db.Close()

	// The database may still be starting. Readiness reports its state, so a
	// failed first ping is logged rather than fatal.
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if err := db.Ping(pingCtx); err != nil {
		logger.Warn("database not reachable at startup", slog.String("error", err.Error()))
	}
	cancel()

	encoder := events.NewEncoder(ids.NewV7, time.Now)
	handler := app.NewHandler(app.Dependencies{
		Logger:      logger,
		Verifier:    oidcverifier.New(ctx, cfg.OIDC),
		Projects:    projects.NewService(db, encoder, ids.NewV7, time.Now),
		ReadyChecks: map[string]httpx.Check{"postgres": db.Ping},
	})

	logger.Info("starting",
		slog.String("commit", version.Commit),
		slog.String("oidc_issuer", cfg.OIDC.Issuer),
		slog.String("oidc_audience", cfg.OIDC.Audience),
	)
	return httpx.Run(ctx, httpx.ServerOptions{
		Addr:            cfg.HTTPAddr,
		Handler:         handler,
		Logger:          logger,
		ShutdownTimeout: cfg.ShutdownTimeout,
	})
}
