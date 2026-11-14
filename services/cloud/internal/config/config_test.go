package config

import (
	"strings"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/config"
)

func env() map[string]string {
	return map[string]string{
		"PF_DATABASE_URL":     "postgres://pf_cloud:x@postgres:5432/parallelf",
		"PF_OIDC_ISSUER":      "http://localhost:8080/realms/parallelf",
		"PF_OIDC_JWKS_URL":    "http://keycloak:8080/realms/parallelf/protocol/openid-connect/certs",
		"PF_CORE_URL":         "http://core:9001",
		"PF_CLOUD_JOIN_TOKEN": "0123456789abcdef0123456789abcdef",
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := Load(config.FromMap(env()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddr != ":9002" || cfg.AgentAddr != ":9102" || cfg.NodeTimeout != 30*time.Second {
		t.Errorf("addresses/timeouts: %+v", cfg)
	}
	if cfg.Overcommit.CPU != 4 || cfg.Overcommit.Memory != 1 {
		t.Errorf("overcommit: %+v", cfg.Overcommit)
	}
	if cfg.DefaultQuota.MaxWorkloads != 10 || cfg.DefaultQuota.MaxMemoryMiB != 8192 {
		t.Errorf("quota: %+v", cfg.DefaultQuota)
	}
}

func TestMissingAndInvalidSettingsAreAllReported(t *testing.T) {
	e := env()
	delete(e, "PF_CORE_URL")
	e["PF_CLOUD_JOIN_TOKEN"] = "short"
	e["PF_CPU_OVERCOMMIT"] = "40"
	_, err := Load(config.FromMap(e))
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"PF_CORE_URL", "PF_CLOUD_JOIN_TOKEN", "PF_CPU_OVERCOMMIT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}
