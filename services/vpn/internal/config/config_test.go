package config

import (
	"strings"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/config"
)

func loader(env map[string]string) *config.Loader {
	base := map[string]string{
		"PF_DATABASE_URL":   "postgres://x",
		"PF_OIDC_ISSUER":    "http://localhost:8080/realms/parallelf",
		"PF_OIDC_JWKS_URL":  "http://keycloak:8080/realms/parallelf/protocol/openid-connect/certs",
		"PF_VPN_JOIN_TOKEN": "a-join-token-that-is-long-enough",
	}
	for k, v := range env {
		base[k] = v
	}
	return config.FromMap(base)
}

func TestDefaults(t *testing.T) {
	cfg, err := Load(loader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tunnel.String() != "10.255.0.0/22" || cfg.ActivationTTL != 8*time.Hour || cfg.MaxAuthAge != 15*time.Minute || cfg.RequireMFA {
		t.Fatalf("defaults %+v", cfg)
	}
}

func TestInvalid(t *testing.T) {
	_, err := Load(loader(map[string]string{
		"PF_VPN_TUNNEL_CIDR":    "10.0.0.0/8",
		"PF_VPN_JOIN_TOKEN":     "short",
		"PF_VPN_ACTIVATION_TTL": "24h",
	}))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, key := range []string{"PF_VPN_TUNNEL_CIDR", "PF_VPN_JOIN_TOKEN", "PF_VPN_ACTIVATION_TTL"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("no error for %s: %v", key, err)
		}
	}
}
