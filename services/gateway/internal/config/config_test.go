package config

import (
	"strings"
	"testing"

	"github.com/commonvtake/parallelf/pkg/config"
)

func TestLoad(t *testing.T) {
	cfg, err := Load(config.FromMap(map[string]string{
		"PF_UPSTREAM_CORE_URL": "http://core:9001/",
		"PF_UPSTREAM_AI_URL":   "http://ai:9006",
		"PF_OIDC_ISSUER":       "http://localhost:8080/realms/parallelf",
		"PF_OIDC_JWKS_URL":     "http://keycloak:8080/realms/parallelf/protocol/openid-connect/certs",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPAddr != ":8000" || cfg.CoreURL.String() != "http://core:9001" || cfg.AIURL.Host != "ai:9006" {
		t.Errorf("unexpected config: %+v", cfg)
	}
}

func TestLoadReportsMissingUpstreams(t *testing.T) {
	_, err := Load(config.FromMap(map[string]string{"PF_UPSTREAM_CORE_URL": "core:9001"}))
	if err == nil {
		t.Fatal("Load succeeded with invalid settings")
	}
	for _, key := range []string{"PF_UPSTREAM_CORE_URL", "PF_UPSTREAM_AI_URL", "PF_OIDC_ISSUER"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error does not mention %s: %v", key, err)
		}
	}
}
