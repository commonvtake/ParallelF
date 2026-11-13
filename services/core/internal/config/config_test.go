package config

import (
	"strings"
	"testing"

	"github.com/commonvtake/parallelf/pkg/config"
)

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load(config.FromMap(map[string]string{
		"PF_DATABASE_URL":  "postgres://pf_core:pw@postgres:5432/parallelf",
		"PF_OIDC_ISSUER":   "http://localhost:8080/realms/parallelf",
		"PF_OIDC_JWKS_URL": "http://keycloak:8080/realms/parallelf/protocol/openid-connect/certs",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPAddr != ":9001" || cfg.LogLevel != "info" || cfg.OIDC.Audience != "parallelf-api" {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadReportsMissingRequiredSettings(t *testing.T) {
	_, err := Load(config.FromMap(nil))
	if err == nil {
		t.Fatal("Load succeeded without required settings")
	}
	for _, key := range []string{"PF_DATABASE_URL", "PF_OIDC_ISSUER", "PF_OIDC_JWKS_URL"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error does not mention %s: %v", key, err)
		}
	}
}
