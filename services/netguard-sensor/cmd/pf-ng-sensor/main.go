// Command pf-ng-sensor runs on the host that carries ParallelF's networks
// (the VPN interface and the Cloud bridges). It supervises Suricata on
// those interfaces only, tails its EVE output, ships normalized events to
// pf-netguardd, and runs discovery scopes that pf-netguardd signed.
//
// It needs root (packet capture) and is meant to run as a systemd service;
// see deploy/systemd.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/commonvtake/parallelf/pkg/config"
	"github.com/commonvtake/parallelf/pkg/logging"
	"github.com/commonvtake/parallelf/pkg/ngsensor"
	"github.com/commonvtake/parallelf/pkg/version"
	"github.com/commonvtake/parallelf/services/netguard-sensor/internal/client"
	sensorconfig "github.com/commonvtake/parallelf/services/netguard-sensor/internal/config"
	"github.com/commonvtake/parallelf/services/netguard-sensor/internal/discovery"
	"github.com/commonvtake/parallelf/services/netguard-sensor/internal/ship"
	"github.com/commonvtake/parallelf/services/netguard-sensor/internal/suricata"
	"github.com/commonvtake/parallelf/services/netguard-sensor/internal/tail"
)

const serviceName = "pf-ng-sensor"

func main() {
	check := flag.Bool("check", false, "print the Suricata version and the interfaces that would be monitored, then exit")
	flag.Parse()
	if err := run(*check); err != nil {
		fmt.Fprintln(os.Stderr, serviceName+":", err)
		os.Exit(1)
	}
}

// queue holds discovery results until a batch delivering them succeeds.
type queue struct {
	mu     sync.Mutex
	events []ngsensor.Event
}

func (q *queue) add(evs []ngsensor.Event) {
	q.mu.Lock()
	q.events = append(q.events, evs...)
	q.mu.Unlock()
}

func (q *queue) peek(max int) []ngsensor.Event {
	q.mu.Lock()
	defer q.mu.Unlock()
	return slices.Clone(q.events[:min(max, len(q.events))])
}

func (q *queue) drop(n int) {
	q.mu.Lock()
	q.events = q.events[n:]
	q.mu.Unlock()
}

func run(checkOnly bool) error {
	cfg, err := sensorconfig.Load(config.FromEnv())
	if err != nil {
		return err
	}
	logger := logging.New(os.Stdout, logging.Options{Service: serviceName, Version: version.Version, Level: cfg.LogLevel})
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sup := &suricata.Supervisor{Binary: cfg.Suricata, DataDir: cfg.DataDir, ETRules: cfg.ExtraRules, Logger: logger}
	engine, err := sup.Version(ctx)
	if err != nil {
		return fmt.Errorf("suricata is not usable: %w", err)
	}
	ifaces := suricata.Interfaces("/sys/class/net", cfg.VPNInterface)
	if checkOnly {
		fmt.Printf("engine: %s\ninterfaces: %v\n", engine, ifaces)
		return nil
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("data directory: %w", err)
	}

	cl := client.New(cfg.NetGuardURL)
	credPath := filepath.Join(cfg.DataDir, "credentials.json")
	register := ngsensor.RegisterRequest{Name: cfg.Name, AgentVersion: version.Version, Engine: engine}
	creds, err := credentials(ctx, cl, cfg, credPath, register, logger, false)
	if err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(creds.ScopePublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("the stored scope-signing key is invalid; delete credentials.json and register again")
	}

	tailer, err := tail.Open(sup.EvePath(), filepath.Join(cfg.DataDir, "eve.position"), ngsensor.MaxLineBytes)
	if err != nil {
		return err
	}
	runner := &discovery.Runner{Key: ed25519.PublicKey(key), Probe: discovery.System{}, Now: time.Now}
	found := &queue{}
	scopes := make(chan ngsensor.Scope, 16)
	go func() {
		for s := range scopes {
			logger.Info("discovery scope started", slog.String("scope_id", s.ID), slog.String("name", s.Name), slog.Any("cidrs", s.CIDRs))
			evs := runner.Run(ctx, s)
			found.add(evs)
			logger.Info("discovery scope finished", slog.String("scope_id", s.ID), slog.Int("results", len(evs)))
		}
	}()
	defer close(scopes)
	defer sup.Stop()

	logger.Info("started", slog.String("sensor", cfg.Name), slog.String("sensor_id", creds.SensorID), slog.String("engine", engine))
	interval := time.Duration(cfg.IntervalSec) * time.Second
	failures := 0
	var lastIfaces []string
	for {
		ifaces = suricata.Interfaces("/sys/class/net", cfg.VPNInterface)
		if !slices.Equal(ifaces, lastIfaces) {
			logger.Info("monitored interfaces", slog.Any("interfaces", ifaces))
			lastIfaces = ifaces
		}
		if err := sup.Ensure(ctx, ifaces); err != nil {
			logger.Error("suricata", slog.String("error", err.Error()))
		}

		disc := found.peek(ngsensor.MaxBatchEvents / 4)
		lines, skipped, err := tailer.Read(ngsensor.MaxBatchEvents - len(disc))
		if err != nil {
			logger.Error("reading eve.json", slog.String("error", err.Error()))
		}
		events, st := ship.Batch(lines)
		events = append(events, disc...)
		if skipped+st.Malformed > 0 {
			logger.Warn("lines dropped", slog.Int("overlong", skipped), slog.Int("malformed", st.Malformed))
		}
		resp, err := cl.Ingest(ctx, creds.Token, ngsensor.IngestRequest{Engine: engine, Interfaces: ifaces, Events: events, EngineError: sup.Err()})
		switch {
		case err == nil:
			failures = 0
			if cerr := tailer.Commit(); cerr != nil {
				logger.Error("saving the eve.json position", slog.String("error", cerr.Error()))
			}
			found.drop(len(disc))
			run, refused := runner.Pending(resp.Scopes)
			for _, reason := range refused {
				logger.Warn("discovery scope refused", slog.String("reason", reason))
			}
			for _, s := range run {
				select {
				case scopes <- s:
				default:
					logger.Warn("discovery queue full; scope skipped", slog.String("scope_id", s.ID))
				}
			}
			if len(lines) < ngsensor.MaxBatchEvents-len(disc) {
				if rerr := sup.Rotate(int64(cfg.MaxEveMB) << 20); rerr != nil {
					logger.Warn("rotating eve.json", slog.String("error", rerr.Error()))
				}
			} else {
				continue // more is waiting: send it at once
			}
		case errors.Is(err, client.ErrUnauthorized):
			logger.Warn("credential rejected; registering again")
			if c, rerr := credentials(ctx, cl, cfg, credPath, register, logger, true); rerr == nil {
				creds = c
				continue
			} else {
				logger.Error("re-registration failed", slog.String("error", rerr.Error()))
			}
			failures++
		default:
			if ctx.Err() != nil {
				logger.Info("stopping")
				return nil
			}
			failures++
			logger.Warn("delivery failed; events stay on disk until it succeeds", slog.String("error", err.Error()), slog.Int("failures", failures))
		}
		wait := interval
		if failures > 0 {
			wait = min(time.Duration(1<<min(failures, 4))*time.Second, 30*time.Second)
		}
		if !sleep(ctx, wait) {
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
func credentials(ctx context.Context, cl *client.Client, cfg sensorconfig.Config, path string,
	req ngsensor.RegisterRequest, logger *slog.Logger, force bool,
) (client.Credentials, error) {
	if !force {
		if c, ok, err := client.Load(path); err != nil {
			return client.Credentials{}, err
		} else if ok && c.NetGuardURL == cfg.NetGuardURL {
			return c, nil
		}
	}
	if cfg.JoinToken == "" {
		return client.Credentials{}, errors.New("not registered and PF_NGS_JOIN_TOKEN is not set")
	}
	for attempt := 1; ; attempt++ {
		resp, err := cl.Register(ctx, cfg.JoinToken, req)
		if err == nil {
			c := client.Credentials{SensorID: resp.SensorID, Token: resp.Credential, Name: cfg.Name, NetGuardURL: cfg.NetGuardURL, ScopePublicKey: resp.ScopePublicKey}
			if err := client.Save(path, c); err != nil {
				return client.Credentials{}, err
			}
			logger.Info("registered", slog.String("sensor_id", c.SensorID))
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
