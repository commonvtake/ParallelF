// Command pf-wg-agent runs on the VPN gateway host. It registers the
// gateway with pf-vpnd (sending only its WireGuard public key), then keeps
// the kernel WireGuard interface and the nftables table inet parallelf_vpn
// converged to the desired state it receives.
//
// It needs root (CAP_NET_ADMIN) and is meant to run as a systemd service;
// see deploy/systemd.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/commonvtake/parallelf/pkg/config"
	"github.com/commonvtake/parallelf/pkg/logging"
	"github.com/commonvtake/parallelf/pkg/version"
	"github.com/commonvtake/parallelf/pkg/vpnagent"
	"github.com/commonvtake/parallelf/services/vpn-agent/internal/agent"
	"github.com/commonvtake/parallelf/services/vpn-agent/internal/client"
	agentconfig "github.com/commonvtake/parallelf/services/vpn-agent/internal/config"
	"github.com/commonvtake/parallelf/services/vpn-agent/internal/hostexec"
	"github.com/commonvtake/parallelf/services/vpn-agent/internal/nft"
	"github.com/commonvtake/parallelf/services/vpn-agent/internal/wg"
)

const serviceName = "pf-wg-agent"

// pollSeconds is how long a sync may wait for a change; the agent reports
// peer statistics at least this often.
const pollSeconds = 10

func main() {
	check := flag.Bool("check", false, "check that wg, ip and nft work on this host, print the result and exit")
	flag.Parse()
	if err := run(*check); err != nil {
		fmt.Fprintln(os.Stderr, serviceName+":", err)
		os.Exit(1)
	}
}

func run(checkOnly bool) error {
	cfg, err := agentconfig.Load(config.FromEnv())
	if err != nil {
		return err
	}
	logger := logging.New(os.Stdout, logging.Options{Service: serviceName, Version: version.Version, Level: cfg.LogLevel})
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runner := hostexec.Exec{Timeout: 20 * time.Second}
	for _, probe := range [][]string{{"wg", "--version"}, {"ip", "-V"}, {"nft", "--version"}} {
		out, err := runner.Run(ctx, nil, probe[0], probe[1:]...)
		if err != nil {
			return fmt.Errorf("%s is not usable: %w", probe[0], err)
		}
		if checkOnly {
			fmt.Printf("%s: %s", probe[0], out)
		}
	}
	if checkOnly {
		fmt.Printf("endpoint: %s\n", cfg.ResolveEndpoint())
		return nil
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("data directory: %w", err)
	}

	manager := &wg.Manager{
		Iface: cfg.Interface, KeyPath: filepath.Join(cfg.DataDir, "private.key"), Run: runner,
		RemoveHook: func(ctx context.Context, addresses []string) { flushConntrack(ctx, runner, addresses, logger) },
	}
	publicKey, err := manager.EnsureKey(ctx)
	if err != nil {
		return fmt.Errorf("gateway key: %w", err)
	}
	endpoint := cfg.ResolveEndpoint()

	cl := client.New(cfg.VPNURL)
	credPath := filepath.Join(cfg.DataDir, "credentials.json")
	register := vpnagent.RegisterRequest{Name: cfg.Name, AgentVersion: version.Version, PublicKey: publicKey, Endpoint: endpoint, ListenPort: cfg.ListenPort}
	creds, err := credentials(ctx, cl, cfg, credPath, register, logger, false)
	if err != nil {
		return err
	}

	ag := &agent.Agent{Iface: cfg.Interface, WG: manager, FW: &nft.Applier{Run: runner}, Now: time.Now, Logger: logger}
	logger.Info("started", slog.String("gateway", cfg.Name), slog.String("gateway_id", creds.GatewayID),
		slog.String("interface", cfg.Interface), slog.String("endpoint", endpoint), slog.String("public_key", publicKey))

	failures, wait := 0, 0
	for {
		req := vpnagent.SyncRequest{
			Revision: ag.Revision(), WaitSeconds: wait, PublicKey: publicKey, Endpoint: endpoint,
			Peers: ag.Observe(ctx), ApplyError: ag.LastError(),
		}
		resp, err := cl.Sync(ctx, creds.Token, req)
		switch {
		case err == nil:
			failures = 0
			if aerr := ag.Apply(ctx, resp); aerr != nil {
				logger.Error("apply failed", slog.String("error", aerr.Error()))
				wait = 0
				sleep(ctx, 3*time.Second)
			} else {
				wait = pollSeconds
			}
			continue
		case errors.Is(err, client.ErrUnauthorized):
			logger.Warn("credential rejected; registering again")
			if c, rerr := credentials(ctx, cl, cfg, credPath, register, logger, true); rerr == nil {
				creds = c
				continue
			} else {
				logger.Error("re-registration failed", slog.String("error", rerr.Error()))
			}
		default:
			if ctx.Err() != nil {
				logger.Info("stopping; the interface and firewall stay in place, and activations still expire in the kernel")
				return nil
			}
			logger.Warn("sync failed; activations still expire on their own", slog.String("error", err.Error()), slog.Int("failures", failures))
		}
		failures++
		wait = 0
		if !sleep(ctx, min(time.Duration(1<<min(failures, 4))*time.Second, 30*time.Second)) {
			logger.Info("stopping")
			return nil
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// credentials loads the stored credential or registers with the join token.
func credentials(ctx context.Context, cl *client.Client, cfg agentconfig.Config, path string,
	req vpnagent.RegisterRequest, logger *slog.Logger, force bool,
) (client.Credentials, error) {
	if !force {
		if c, ok, err := client.Load(path); err != nil {
			return client.Credentials{}, err
		} else if ok && c.VPNURL == cfg.VPNURL {
			return c, nil
		}
	}
	if cfg.JoinToken == "" {
		return client.Credentials{}, errors.New("not registered and PF_WGA_JOIN_TOKEN is not set")
	}
	for attempt := 1; ; attempt++ {
		resp, err := cl.Register(ctx, cfg.JoinToken, req)
		if err == nil {
			c := client.Credentials{GatewayID: resp.GatewayID, Token: resp.Credential, Name: cfg.Name, VPNURL: cfg.VPNURL}
			if err := client.Save(path, c); err != nil {
				return client.Credentials{}, err
			}
			logger.Info("registered", slog.String("gateway_id", c.GatewayID))
			return c, nil
		}
		if errors.Is(err, client.ErrUnauthorized) {
			return client.Credentials{}, errors.New("the join token was rejected")
		}
		logger.Warn("registration failed; retrying", slog.String("error", err.Error()), slog.Int("attempt", attempt))
		if !sleep(ctx, min(time.Duration(attempt)*2*time.Second, 30*time.Second)) {
			return client.Credentials{}, ctx.Err()
		}
	}
}

// flushConntrack ends established connections of removed peers at once.
// conntrack(8) exits non-zero when nothing matched, which is not an error.
func flushConntrack(ctx context.Context, run hostexec.Runner, addresses []string, logger *slog.Logger) {
	for _, a := range addresses {
		for _, dir := range []string{"-s", "-d"} {
			if _, err := run.Run(ctx, nil, "conntrack", "-D", dir, a); err != nil {
				logger.Debug("conntrack flush", slog.String("address", a), slog.String("error", err.Error()))
			}
		}
	}
}
