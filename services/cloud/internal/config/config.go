// Package config defines pf-cloudd's runtime configuration.
package config

import (
	"net/url"
	"time"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/config"
	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
)

// Config holds every setting pf-cloudd reads from the environment.
type Config struct {
	// HTTPAddr serves the user API (reached through pf-gateway).
	HTTPAddr string
	// AgentAddr serves the node-agent protocol. It is published only on the
	// host's loopback interface in the local stack.
	AgentAddr        string
	LogLevel         string
	DatabaseURL      string
	OIDC             authn.OIDCSettings
	CoreURL          *url.URL
	JoinToken        string
	NodeTimeout      time.Duration
	MetricsRetention time.Duration
	Overcommit       domain.Overcommit
	DefaultQuota     domain.Quota
	ShutdownTimeout  time.Duration
}

// Load reads and validates the configuration.
func Load(l *config.Loader) (Config, error) {
	cfg := Config{
		HTTPAddr:         l.String("PF_HTTP_ADDR", ":9002"),
		AgentAddr:        l.String("PF_AGENT_ADDR", ":9102"),
		LogLevel:         l.OneOf("PF_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		DatabaseURL:      l.Secret("PF_DATABASE_URL"),
		OIDC:             authn.LoadOIDCSettings(l),
		CoreURL:          l.URL("PF_CORE_URL"),
		JoinToken:        l.Secret("PF_CLOUD_JOIN_TOKEN"),
		NodeTimeout:      l.Duration("PF_NODE_TIMEOUT", 30*time.Second),
		MetricsRetention: l.Duration("PF_METRICS_RETENTION", 24*time.Hour),
		Overcommit: domain.Overcommit{
			CPU:    float64(l.Int("PF_CPU_OVERCOMMIT", 4, 1, 16)),
			Memory: 1,
			Disk:   1,
		},
		DefaultQuota: domain.Quota{
			MaxVCPUs:     l.Int("PF_DEFAULT_QUOTA_VCPUS", 8, 0, 1_000_000),
			MaxMemoryMiB: l.Int("PF_DEFAULT_QUOTA_MEMORY_MIB", 8192, 0, 1_000_000),
			MaxDiskGiB:   l.Int("PF_DEFAULT_QUOTA_DISK_GIB", 100, 0, 1_000_000),
			MaxWorkloads: l.Int("PF_DEFAULT_QUOTA_WORKLOADS", 10, 0, 1_000_000),
		},
		ShutdownTimeout: l.Duration("PF_SHUTDOWN_TIMEOUT", 10*time.Second),
	}
	if cfg.JoinToken != "" && len(cfg.JoinToken) < 24 {
		l.Invalid("PF_CLOUD_JOIN_TOKEN", "must be at least 24 characters")
	}
	return cfg, l.Err()
}
