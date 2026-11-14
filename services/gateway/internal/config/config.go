// Package config defines pf-gateway's runtime configuration.
package config

import (
	"net/url"
	"time"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/config"
)

// Config holds every setting pf-gateway reads from the environment.
type Config struct {
	HTTPAddr        string
	LogLevel        string
	CoreURL         *url.URL
	CloudURL        *url.URL
	AIURL           *url.URL
	OIDC            authn.OIDCSettings
	ShutdownTimeout time.Duration
}

// Load reads and validates the configuration.
func Load(l *config.Loader) (Config, error) {
	cfg := Config{
		HTTPAddr:        l.String("PF_HTTP_ADDR", ":8000"),
		LogLevel:        l.OneOf("PF_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		CoreURL:         l.URL("PF_UPSTREAM_CORE_URL"),
		CloudURL:        l.URL("PF_UPSTREAM_CLOUD_URL"),
		AIURL:           l.URL("PF_UPSTREAM_AI_URL"),
		OIDC:            authn.LoadOIDCSettings(l),
		ShutdownTimeout: l.Duration("PF_SHUTDOWN_TIMEOUT", 10*time.Second),
	}
	return cfg, l.Err()
}
