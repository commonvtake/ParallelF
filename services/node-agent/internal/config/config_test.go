package config

import (
	"strings"
	"testing"

	"github.com/commonvtake/parallelf/pkg/config"
)

func TestDefaultsAndValidation(t *testing.T) {
	cfg, err := Load(config.FromMap(map[string]string{"PF_AGENT_CLOUD_URL": "http://localhost:9102", "PF_AGENT_NAME": "host-1"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "/var/lib/parallelf/cloud" || cfg.LibvirtURI != "qemu:///system" || cfg.ReservedMemoryMiB != 4096 || !cfg.EnableVMs {
		t.Fatalf("defaults: %+v", cfg)
	}
	_, err = Load(config.FromMap(map[string]string{"PF_AGENT_NAME": "Bad Name", "PF_AGENT_DATA_DIR": "relative"}))
	for _, want := range []string{"PF_AGENT_CLOUD_URL", "PF_AGENT_NAME", "PF_AGENT_DATA_DIR"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s: %v", want, err)
		}
	}
}

func TestDefaultNameIsValid(t *testing.T) {
	name := DefaultName()
	if name == "" || strings.ToLower(name) != name || len(name) > 63 {
		t.Fatalf("got %q", name)
	}
}
