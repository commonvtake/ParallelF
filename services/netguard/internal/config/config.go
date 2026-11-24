// Package config defines pf-netguardd's runtime configuration.
package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/netip"
	"strings"
	"time"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/config"
)

// Config holds every setting pf-netguardd reads from the environment.
type Config struct {
	HTTPAddr    string // user API, reached through pf-gateway
	SensorAddr  string // sensor protocol, loopback only in the stack
	LogLevel    string
	DatabaseURL string
	OIDC        authn.OIDCSettings
	JoinToken   string
	ScopeKey    ed25519.PrivateKey
	// Monitored are ranges ParallelF owns besides Cloud networks (which
	// NetGuard learns from Cloud events): by default the VPN tunnel.
	Monitored []netip.Prefix
	// Infrastructure are the platform's own addresses (address=name).
	Infrastructure  map[string]string
	EventRetention  time.Duration
	MaxAuthAge      time.Duration
	ExemptClients   []string
	ShutdownTimeout time.Duration
}

// Load reads and validates the configuration.
func Load(l *config.Loader) (Config, error) {
	cfg := Config{
		HTTPAddr:        l.String("PF_HTTP_ADDR", ":9004"),
		SensorAddr:      l.String("PF_SENSOR_ADDR", ":9104"),
		LogLevel:        l.OneOf("PF_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		DatabaseURL:     l.Secret("PF_DATABASE_URL"),
		OIDC:            authn.LoadOIDCSettings(l),
		JoinToken:       l.Secret("PF_NG_JOIN_TOKEN"),
		EventRetention:  l.Duration("PF_NG_EVENT_RETENTION", 7*24*time.Hour),
		MaxAuthAge:      l.Duration("PF_NG_MAX_AUTH_AGE", 15*time.Minute),
		ExemptClients:   splitList(l.String("PF_NG_STEP_UP_EXEMPT_CLIENTS", "")),
		ShutdownTimeout: l.Duration("PF_SHUTDOWN_TIMEOUT", 10*time.Second),
		Infrastructure:  map[string]string{},
	}
	if len(cfg.JoinToken) < 24 {
		l.Invalid("PF_NG_JOIN_TOKEN", "must be at least 24 characters")
	}
	seed, err := base64.StdEncoding.DecodeString(l.Secret("PF_NG_SCOPE_SIGNING_KEY"))
	if err != nil || len(seed) != ed25519.SeedSize {
		l.Invalid("PF_NG_SCOPE_SIGNING_KEY", "must be 32 bytes, base64 (make init generates it)")
	} else {
		cfg.ScopeKey = ed25519.NewKeyFromSeed(seed)
	}
	for _, c := range splitList(l.String("PF_NG_MONITORED_CIDRS", "10.255.0.0/22")) {
		p, err := netip.ParsePrefix(c)
		if err != nil || !p.Addr().Is4() || !p.Addr().IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(p.Addr()) {
			l.Invalid("PF_NG_MONITORED_CIDRS", "%q must be a private IPv4 CIDR", c)
			continue
		}
		cfg.Monitored = append(cfg.Monitored, p.Masked())
	}
	for _, item := range splitList(l.String("PF_NG_INFRA_ADDRESSES", "10.255.0.1=vpn-gateway")) {
		ip, name, _ := strings.Cut(item, "=")
		a, err := netip.ParseAddr(ip)
		if err != nil || name == "" || len(name) > 64 {
			l.Invalid("PF_NG_INFRA_ADDRESSES", "%q must be address=name", item)
			continue
		}
		cfg.Infrastructure[a.String()] = name
	}
	if cfg.EventRetention < time.Hour {
		l.Invalid("PF_NG_EVENT_RETENTION", "must be at least 1h")
	}
	return cfg, l.Err()
}

func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
