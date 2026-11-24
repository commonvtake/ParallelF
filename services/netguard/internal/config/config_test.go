package config

import (
	"strings"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/config"
)

func loader(env map[string]string) *config.Loader {
	base := map[string]string{
		"PF_DATABASE_URL":         "postgres://x",
		"PF_OIDC_ISSUER":          "http://localhost:8080/realms/parallelf",
		"PF_OIDC_JWKS_URL":        "http://keycloak:8080/realms/parallelf/protocol/openid-connect/certs",
		"PF_NG_JOIN_TOKEN":        "a-join-token-that-is-long-enough",
		"PF_NG_SCOPE_SIGNING_KEY": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
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
	if len(cfg.Monitored) != 1 || cfg.Monitored[0].String() != "10.255.0.0/22" || cfg.Infrastructure["10.255.0.1"] != "vpn-gateway" ||
		cfg.EventRetention != 7*24*time.Hour || len(cfg.ScopeKey) != 64 {
		t.Fatalf("defaults %+v", cfg)
	}
}

func TestInvalid(t *testing.T) {
	_, err := Load(loader(map[string]string{
		"PF_NG_JOIN_TOKEN":        "short",
		"PF_NG_SCOPE_SIGNING_KEY": "c2hvcnQ=",
		"PF_NG_MONITORED_CIDRS":   "8.8.8.0/24",
		"PF_NG_INFRA_ADDRESSES":   "nonsense",
	}))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, key := range []string{"PF_NG_JOIN_TOKEN", "PF_NG_SCOPE_SIGNING_KEY", "PF_NG_MONITORED_CIDRS", "PF_NG_INFRA_ADDRESSES"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("no error for %s: %v", key, err)
		}
	}
}
