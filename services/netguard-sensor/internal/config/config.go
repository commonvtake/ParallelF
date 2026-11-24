// Package config defines pf-ng-sensor's runtime configuration.
package config

import (
	"os"
	"regexp"
	"strings"

	"github.com/commonvtake/parallelf/pkg/config"
)

// Config holds every setting the sensor reads from the environment.
type Config struct {
	NetGuardURL  string
	JoinToken    string // only needed until the sensor has registered
	Name         string
	DataDir      string
	VPNInterface string
	Suricata     string // binary
	ExtraRules   string // optional rules file, e.g. ET Open from suricata-update
	IntervalSec  int
	MaxEveMB     int
	LogLevel     string
}

var (
	namePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
	ifacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
	invalidName  = regexp.MustCompile(`[^a-z0-9.-]+`)
)

func defaultName() string {
	h, err := os.Hostname()
	if err != nil {
		return "sensor"
	}
	name := strings.Trim(invalidName.ReplaceAllString(strings.ToLower(h), "-"), "-.")
	if name == "" || len(name) > 63 {
		return "sensor"
	}
	return name
}

// Load reads and validates the configuration.
func Load(l *config.Loader) (Config, error) {
	cfg := Config{
		NetGuardURL:  l.URL("PF_NGS_NETGUARD_URL").String(),
		JoinToken:    l.String("PF_NGS_JOIN_TOKEN", ""),
		Name:         l.String("PF_NGS_NAME", defaultName()),
		DataDir:      l.String("PF_NGS_DATA_DIR", "/var/lib/parallelf/netguard"),
		VPNInterface: l.String("PF_NGS_VPN_INTERFACE", "wg-pf0"),
		Suricata:     l.String("PF_NGS_SURICATA", "suricata"),
		ExtraRules:   l.String("PF_NGS_EXTRA_RULES", ""),
		IntervalSec:  l.Int("PF_NGS_INTERVAL_SECONDS", 2, 1, 60),
		MaxEveMB:     l.Int("PF_NGS_MAX_EVE_MB", 256, 16, 4096),
		LogLevel:     l.OneOf("PF_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
	}
	if !namePattern.MatchString(cfg.Name) {
		l.Invalid("PF_NGS_NAME", "must be lower-case letters, digits, dots and hyphens")
	}
	if !strings.HasPrefix(cfg.DataDir, "/") {
		l.Invalid("PF_NGS_DATA_DIR", "must be an absolute path")
	}
	if !ifacePattern.MatchString(cfg.VPNInterface) {
		l.Invalid("PF_NGS_VPN_INTERFACE", "must be a valid interface name (at most 15 characters)")
	}
	return cfg, l.Err()
}
