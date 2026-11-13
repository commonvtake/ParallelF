// Command pf-gateway is the single entry point to the ParallelF API. It
// authenticates requests and routes them to the owning service.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/commonvtake/parallelf/pkg/authn/oidcverifier"
	"github.com/commonvtake/parallelf/pkg/config"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/logging"
	"github.com/commonvtake/parallelf/pkg/version"
	"github.com/commonvtake/parallelf/services/gateway/internal/app"
	gatewayconfig "github.com/commonvtake/parallelf/services/gateway/internal/config"
	"github.com/commonvtake/parallelf/services/gateway/internal/proxy"
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
	cfg, err := gatewayconfig.Load(config.FromEnv())
	if err != nil {
		return err
	}
	logger := logging.New(os.Stdout, logging.Options{Service: app.ServiceName, Version: version.Version, Level: cfg.LogLevel})
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	handler := app.NewHandler(cfg, oidcverifier.New(ctx, cfg.OIDC), proxy.NewTransport(), logger)

	logger.Info("starting",
		slog.String("commit", version.Commit),
		slog.String("core_url", cfg.CoreURL.String()),
		slog.String("ai_url", cfg.AIURL.String()),
		slog.String("oidc_issuer", cfg.OIDC.Issuer),
	)
	return httpx.Run(ctx, httpx.ServerOptions{
		Addr:            cfg.HTTPAddr,
		Handler:         handler,
		Logger:          logger,
		ShutdownTimeout: cfg.ShutdownTimeout,
	})
}
