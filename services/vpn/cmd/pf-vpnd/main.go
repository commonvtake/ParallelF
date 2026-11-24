// Command pf-vpnd is the ParallelF VPN control plane: device enrolment,
// activations, access policies and the endpoint WireGuard gateway agents
// synchronise with.
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
	"github.com/commonvtake/parallelf/services/vpn/internal/agentapi"
	"github.com/commonvtake/parallelf/services/vpn/internal/api"
	"github.com/commonvtake/parallelf/services/vpn/internal/app"
	vpnconfig "github.com/commonvtake/parallelf/services/vpn/internal/config"
	"github.com/commonvtake/parallelf/services/vpn/internal/controller"
	"github.com/commonvtake/parallelf/services/vpn/internal/events"
	"github.com/commonvtake/parallelf/services/vpn/internal/pskcrypt"
	"github.com/commonvtake/parallelf/services/vpn/internal/store"
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
	cfg, err := vpnconfig.Load(config.FromEnv())
	if err != nil {
		return err
	}
	logger := logging.New(os.Stdout, logging.Options{Service: app.ServiceName, Version: version.Version, Level: cfg.LogLevel})
	slog.SetDefault(logger)

	var psk store.PSKBox
	if cfg.PSKKey != "" {
		box, err := pskcrypt.New(cfg.PSKKey)
		if err != nil {
			return fmt.Errorf("PF_VPN_PSK_KEY: %w", err)
		}
		psk = box
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DatabaseURL, store.Options{
		Encoder: events.NewEncoder(ids.NewV7, time.Now), PSK: psk, NewID: ids.NewV7, Now: time.Now,
		Tunnel: cfg.Tunnel, DeviceTTL: cfg.DeviceTTL,
	})
	if err != nil {
		return err
	}
	defer db.Close()

	ctrl := controller.New(db, controller.Options{GatewayTimeout: cfg.GatewayTimeout, StatsRetention: cfg.StatsRetention}, logger)
	userAPI := api.New(db, api.Activation{
		Default: cfg.ActivationTTL, Min: cfg.ActivationMin, Max: cfg.ActivationMax,
		MaxAuthAge: cfg.MaxAuthAge, RequireMFA: cfg.RequireMFA, ExemptClients: cfg.ExemptClients,
	}, cfg.Tunnel, logger)
	deps := app.Dependencies{
		Logger:      logger,
		Verifier:    oidcverifier.New(ctx, cfg.OIDC),
		API:         userAPI,
		AgentAPI:    agentapi.New(db, cfg.JoinToken, logger),
		ReadyChecks: map[string]httpx.Check{"postgres": db.Ping},
	}
	logger.Info("starting", slog.String("commit", version.Commit), slog.String("api_addr", cfg.HTTPAddr),
		slog.String("agent_addr", cfg.AgentAddr), slog.String("tunnel", cfg.Tunnel.String()),
		slog.Bool("preshared_keys", psk != nil), slog.Duration("max_auth_age", cfg.MaxAuthAge), slog.Bool("require_mfa", cfg.RequireMFA), slog.Any("step_up_exempt_clients", cfg.ExemptClients))

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
