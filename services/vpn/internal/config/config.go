// Package config defines pf-vpnd's runtime configuration.
package config

import (
	"net/netip"
	"strings"
	"time"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/config"
)

// Config holds every setting pf-vpnd reads from the environment.
type Config struct {
	HTTPAddr        string // user API, reached through pf-gateway
	AgentAddr       string // gateway-agent protocol, loopback only in the stack
	LogLevel        string
	DatabaseURL     string
	OIDC            authn.OIDCSettings
	JoinToken       string
	PSKKey          string // base64 32-byte KEK; empty disables pre-shared keys
	Tunnel          netip.Prefix
	DeviceTTL       time.Duration
	GatewayTimeout  time.Duration
	StatsRetention  time.Duration
	ActivationTTL   time.Duration
	ActivationMin   time.Duration
	ActivationMax   time.Duration
	MaxAuthAge      time.Duration
	RequireMFA      bool
	ExemptClients   []string
	ShutdownTimeout time.Duration
}

// Load reads and validates the configuration.
func Load(l *config.Loader) (Config, error) {
	cfg := Config{
		HTTPAddr:        l.String("PF_HTTP_ADDR", ":9003"),
		AgentAddr:       l.String("PF_AGENT_ADDR", ":9103"),
		LogLevel:        l.OneOf("PF_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		DatabaseURL:     l.Secret("PF_DATABASE_URL"),
		OIDC:            authn.LoadOIDCSettings(l),
		JoinToken:       l.Secret("PF_VPN_JOIN_TOKEN"),
		PSKKey:          l.String("PF_VPN_PSK_KEY", ""),
		DeviceTTL:       l.Duration("PF_VPN_DEVICE_TTL", 90*24*time.Hour),
		GatewayTimeout:  l.Duration("PF_VPN_GATEWAY_TIMEOUT", 45*time.Second),
		StatsRetention:  l.Duration("PF_VPN_STATS_RETENTION", 7*24*time.Hour),
		ActivationTTL:   l.Duration("PF_VPN_ACTIVATION_TTL", 8*time.Hour),
		ActivationMin:   l.Duration("PF_VPN_ACTIVATION_MIN", 30*time.Second),
		ActivationMax:   l.Duration("PF_VPN_ACTIVATION_MAX", 12*time.Hour),
		MaxAuthAge:      l.Duration("PF_VPN_MAX_AUTH_AGE", 15*time.Minute),
		RequireMFA:      l.Bool("PF_VPN_REQUIRE_MFA", false),
		ExemptClients:   splitList(l.String("PF_VPN_STEP_UP_EXEMPT_CLIENTS", "")),
		ShutdownTimeout: l.Duration("PF_SHUTDOWN_TIMEOUT", 10*time.Second),
	}
	tunnel, err := netip.ParsePrefix(l.String("PF_VPN_TUNNEL_CIDR", "10.255.0.0/22"))
	switch {
	case err != nil || !tunnel.Addr().Is4():
		l.Invalid("PF_VPN_TUNNEL_CIDR", "must be an IPv4 CIDR")
	case tunnel.Bits() < 16 || tunnel.Bits() > 28:
		l.Invalid("PF_VPN_TUNNEL_CIDR", "must be between /16 and /28")
	default:
		cfg.Tunnel = tunnel.Masked()
	}
	if cfg.JoinToken != "" && len(cfg.JoinToken) < 24 {
		l.Invalid("PF_VPN_JOIN_TOKEN", "must be at least 24 characters")
	}
	if cfg.ActivationMin <= 0 || cfg.ActivationMin > cfg.ActivationMax ||
		cfg.ActivationTTL < cfg.ActivationMin || cfg.ActivationTTL > cfg.ActivationMax {
		l.Invalid("PF_VPN_ACTIVATION_TTL", "need 0 < PF_VPN_ACTIVATION_MIN <= PF_VPN_ACTIVATION_TTL <= PF_VPN_ACTIVATION_MAX")
	}
	if cfg.DeviceTTL < time.Hour {
		l.Invalid("PF_VPN_DEVICE_TTL", "must be at least 1h")
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
