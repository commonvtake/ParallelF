package suricata

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestInterfaces(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"eth0", "wg-pf0", "pfbr-0a1b2c3d", "pfbr-ffffffff", "docker0", "lo"} {
		_ = os.Mkdir(filepath.Join(dir, n), 0o755)
	}
	got := Interfaces(dir, "wg-pf0")
	if !reflect.DeepEqual(got, []string{"pfbr-0a1b2c3d", "pfbr-ffffffff", "wg-pf0"}) {
		t.Fatalf("got %v", got)
	}
}

func TestRenderConfig(t *testing.T) {
	cfg, err := RenderConfig([]string{"pfbr-0a1b2c3d", "wg-pf0"}, "/var/lib/parallelf/netguard/suricata")
	if err != nil {
		t.Fatal(err)
	}
	s := string(cfg)
	for _, want := range []string{"community-id: yes", "  - interface: wg-pf0\n    cluster-id: 98", "  - interface: pfbr-0a1b2c3d\n    cluster-id: 99", "host-mode: sniffer-only", `default-log-dir: "/var/lib/parallelf/netguard/suricata"`} {
		if !strings.Contains(s, want) {
			t.Errorf("config lacks %q", want)
		}
	}
	if _, err := RenderConfig([]string{"eth0\n  - interface: x"}, "/x"); err == nil {
		t.Fatal("an interface name must not inject YAML")
	}
}
