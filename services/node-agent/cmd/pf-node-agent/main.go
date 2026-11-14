// Command pf-node-agent runs on a compute host. It registers the host with
// pf-cloudd, then repeatedly reports what runs on the host and converges
// it to the desired state it receives: KVM virtual machines through
// libvirt and containers through Docker.
//
// It needs root (or membership of the libvirt, kvm and docker groups) and
// is meant to run as a systemd service; see deploy/systemd.
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

	"github.com/commonvtake/parallelf/pkg/cloudagent"
	"github.com/commonvtake/parallelf/pkg/config"
	"github.com/commonvtake/parallelf/pkg/logging"
	"github.com/commonvtake/parallelf/pkg/version"
	"github.com/commonvtake/parallelf/services/node-agent/internal/agent"
	"github.com/commonvtake/parallelf/services/node-agent/internal/client"
	agentconfig "github.com/commonvtake/parallelf/services/node-agent/internal/config"
	"github.com/commonvtake/parallelf/services/node-agent/internal/docker"
	"github.com/commonvtake/parallelf/services/node-agent/internal/host"
	"github.com/commonvtake/parallelf/services/node-agent/internal/libvirt"
	"github.com/commonvtake/parallelf/services/node-agent/internal/runtime"
)

const serviceName = "pf-node-agent"

// metricsInterval is how often a host utilisation sample is sent.
const metricsInterval = 10 * time.Second

func main() {
	check := flag.Bool("check", false, "check which runtimes work on this host, print the result and exit")
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
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("data directory: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runtimes, info := probe(ctx, cfg, logger)
	if checkOnly {
		fmt.Printf("node %s: KVM=%v Docker=%v %s\n", cfg.Name, info.KVM, info.Docker, info.Hypervisor)
		if len(runtimes) == 0 {
			return errors.New("no runtime is usable on this host")
		}
		return nil
	}
	if len(runtimes) == 0 {
		return errors.New("no runtime is usable on this host (run with -check for details)")
	}

	sampler := host.NewSampler(cfg.DataDir)
	refreshCapacity := func() {
		cpus, mem, disk, err := sampler.Capacity()
		if err != nil {
			logger.Warn("read host capacity", slog.String("error", err.Error()))
			return
		}
		info.CPUCount, info.MemoryMiB, info.DiskGiB = cpus, mem, disk
	}
	refreshCapacity()

	cl := client.New(cfg.CloudURL)
	credPath := filepath.Join(cfg.DataDir, "credentials.json")
	creds, err := credentials(ctx, cl, cfg, credPath, info, logger, false)
	if err != nil {
		return err
	}

	ag, err := agent.New(cfg.DataDir, runtimes, logger)
	if err != nil {
		return err
	}
	done := make(chan struct{})
	go func() { ag.RunReconciler(ctx, 15*time.Second); close(done) }()

	logger.Info("started", slog.String("node", cfg.Name), slog.String("node_id", creds.NodeID),
		slog.String("cloud_url", cfg.CloudURL), slog.Bool("kvm", info.KVM), slog.Bool("docker", info.Docker))

	interval, failures := 3*time.Second, 0
	var lastMetrics time.Time
	_, _ = sampler.Sample(time.Now()) // prime the CPU counters
	for {
		refreshCapacity()
		req := cloudagent.SyncRequest{AgentVersion: version.Version, Node: info, Workloads: ag.Observe(ctx)}
		if time.Since(lastMetrics) >= metricsInterval {
			if m, err := sampler.Sample(time.Now()); err == nil {
				req.Metrics = &m
				lastMetrics = time.Now()
			}
		}

		resp, err := cl.Sync(ctx, creds.Token, req)
		switch {
		case err == nil:
			failures = 0
			ag.SetDesired(resp)
			if resp.SyncIntervalSeconds > 0 {
				interval = time.Duration(resp.SyncIntervalSeconds) * time.Second
			}
		case errors.Is(err, client.ErrUnauthorized):
			logger.Warn("credential rejected; registering again")
			if c, rerr := credentials(ctx, cl, cfg, credPath, info, logger, true); rerr == nil {
				creds = c
				continue
			} else {
				logger.Error("re-registration failed", slog.String("error", rerr.Error()))
			}
			failures++
		default:
			failures++
			if ctx.Err() == nil {
				logger.Warn("sync failed; workloads keep running", slog.String("error", err.Error()), slog.Int("failures", failures))
			}
		}

		wait := interval
		if failures > 0 {
			wait = min(time.Duration(1<<min(failures, 4))*time.Second, 30*time.Second)
		}
		select {
		case <-ctx.Done():
			logger.Info("stopping; workloads are left running")
			<-done
			return nil
		case <-ag.ReportWake():
		case <-time.After(wait):
		}
	}
}

// probe checks each enabled runtime and describes the node.
func probe(ctx context.Context, cfg agentconfig.Config, logger *slog.Logger) ([]runtime.Runtime, cloudagent.NodeInfo) {
	info := cloudagent.NodeInfo{
		ReservedCPUs: cfg.ReservedCPUs, ReservedMemoryMiB: int64(cfg.ReservedMemoryMiB), ReservedDiskGiB: int64(cfg.ReservedDiskGiB),
	}
	var runtimes []runtime.Runtime
	if cfg.EnableVMs {
		vm := libvirt.New(cfg.LibvirtURI, cfg.DataDir, libvirt.ExecRunner{Timeout: 2 * time.Minute})
		if v, err := vm.Probe(ctx); err != nil {
			logger.Warn("virtual machines disabled", slog.String("reason", err.Error()))
		} else {
			info.KVM, info.Hypervisor = true, v
			runtimes = append(runtimes, vm)
		}
	}
	if cfg.EnableContainers {
		ctr := docker.New(cfg.DockerSocket)
		if v, err := ctr.Probe(ctx); err != nil {
			logger.Warn("containers disabled", slog.String("reason", err.Error()))
		} else {
			info.Docker = true
			if info.Hypervisor != "" {
				info.Hypervisor += ", "
			}
			info.Hypervisor += v
			runtimes = append(runtimes, ctr)
		}
	}
	return runtimes, info
}

// credentials returns stored credentials or registers with the join token.
func credentials(ctx context.Context, cl *client.Client, cfg agentconfig.Config, path string,
	info cloudagent.NodeInfo, logger *slog.Logger, force bool) (client.Credentials, error) {
	if !force {
		c, ok, err := client.LoadCredentials(path)
		if err != nil {
			return client.Credentials{}, err
		}
		if ok && c.Name == cfg.Name && c.CloudURL == cfg.CloudURL {
			return c, nil
		}
	}
	if cfg.JoinToken == "" {
		return client.Credentials{}, errors.New("not registered yet: set PF_AGENT_JOIN_TOKEN (PF_CLOUD_JOIN_TOKEN in the platform's .env)")
	}
	for attempt := 1; ; attempt++ {
		resp, err := cl.Register(ctx, cfg.JoinToken, cloudagent.RegisterRequest{Name: cfg.Name, AgentVersion: version.Version, Node: info})
		if err == nil {
			c := client.Credentials{NodeID: resp.NodeID, Token: resp.Token, Name: cfg.Name, CloudURL: cfg.CloudURL}
			if err := client.SaveCredentials(path, c); err != nil {
				return client.Credentials{}, err
			}
			logger.Info("registered", slog.String("node_id", resp.NodeID))
			return c, nil
		}
		if errors.Is(err, client.ErrUnauthorized) {
			return client.Credentials{}, errors.New("the control plane rejected the join token")
		}
		logger.Warn("registration failed; retrying", slog.String("error", err.Error()), slog.Int("attempt", attempt))
		select {
		case <-ctx.Done():
			return client.Credentials{}, ctx.Err()
		case <-time.After(min(time.Duration(attempt)*2*time.Second, 30*time.Second)):
		}
	}
}
