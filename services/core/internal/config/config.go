// Package config defines pf-core's runtime configuration.
package config

import (
	"time"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/config"
)

// Config holds every setting pf-core reads from the environment.
type Config struct {
	HTTPAddr        string
	LogLevel        string
	DatabaseURL     string
	OIDC            authn.OIDCSettings
	ShutdownTimeout time.Duration
}

// Load reads and validates the configuration.
func Load(l *config.Loader) (Config, error) {
	cfg := Config{
		HTTPAddr:        l.String("PF_HTTP_ADDR", ":9001"),
		LogLevel:        l.OneOf("PF_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		DatabaseURL:     l.Secret("PF_DATABASE_URL"),
		OIDC:            authn.LoadOIDCSettings(l),
		ShutdownTimeout: l.Duration("PF_SHUTDOWN_TIMEOUT", 10*time.Second),
	}
	return cfg, l.Err()
}
