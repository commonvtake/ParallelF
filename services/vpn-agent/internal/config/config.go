// Package config defines pf-wg-agent's runtime configuration.
package config

import (
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/commonvtake/parallelf/pkg/config"
)

// Config holds every setting the agent reads from the environment.
type Config struct {
	VPNURL     string
	JoinToken  string // only needed until the gateway has registered
	Name       string
	DataDir    string
	Interface  string
	ListenPort int
	// Endpoint is the host:port clients dial; derived from the host's first
	// non-loopback IPv4 address when unset.
	Endpoint string
	LogLevel string
}

var (
	namePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
	ifacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
	invalidName  = regexp.MustCompile(`[^a-z0-9.-]+`)
)

func defaultName() string {
	h, err := os.Hostname()
	if err != nil {
		return "gateway"
	}
	name := strings.Trim(invalidName.ReplaceAllString(strings.ToLower(h), "-"), "-.")
	if name == "" || len(name) > 63 {
		return "gateway"
	}
	return name
}

// Load reads and validates the configuration.
func Load(l *config.Loader) (Config, error) {
	cfg := Config{
		VPNURL:     l.URL("PF_WGA_VPN_URL").String(),
		JoinToken:  l.String("PF_WGA_JOIN_TOKEN", ""),
		Name:       l.String("PF_WGA_NAME", defaultName()),
		DataDir:    l.String("PF_WGA_DATA_DIR", "/var/lib/parallelf/vpn"),
		Interface:  l.String("PF_WGA_INTERFACE", "wg-pf0"),
		ListenPort: l.Int("PF_WGA_LISTEN_PORT", 51820, 1, 65535),
		Endpoint:   l.String("PF_WGA_ENDPOINT", ""),
		LogLevel:   l.OneOf("PF_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
	}
	if !namePattern.MatchString(cfg.Name) {
		l.Invalid("PF_WGA_NAME", "must be lower-case letters, digits, dots and hyphens")
	}
	if !strings.HasPrefix(cfg.DataDir, "/") {
		l.Invalid("PF_WGA_DATA_DIR", "must be an absolute path")
	}
	if !ifacePattern.MatchString(cfg.Interface) {
		l.Invalid("PF_WGA_INTERFACE", "must be a valid interface name (at most 15 characters)")
	}
	if cfg.Endpoint != "" {
		if _, port, err := net.SplitHostPort(cfg.Endpoint); err != nil || port == "" {
			l.Invalid("PF_WGA_ENDPOINT", "must be host:port")
		}
	}
	return cfg, l.Err()
}

// ResolveEndpoint returns cfg.Endpoint, or <first non-loopback IPv4>:port.
func (c Config) ResolveEndpoint() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	host := "127.0.0.1"
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() && !strings.HasPrefix(ipn.IP.String(), "10.255.") {
				host = ipn.IP.String()
				break
			}
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(c.ListenPort))
}
