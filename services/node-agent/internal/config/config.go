// Package config defines pf-node-agent's runtime configuration.
package config

import (
	"os"
	"regexp"
	"strings"

	"github.com/commonvtake/parallelf/pkg/config"
)

// Config holds every setting the agent reads from the environment.
type Config struct {
	CloudURL          string
	JoinToken         string // only needed until the node has registered
	Name              string
	DataDir           string
	LibvirtURI        string
	DockerSocket      string
	EnableVMs         bool
	EnableContainers  bool
	ReservedCPUs      int
	ReservedMemoryMiB int
	ReservedDiskGiB   int
	LogLevel          string
}

var invalidName = regexp.MustCompile(`[^a-z0-9.-]+`)

// DefaultName derives a node name from the hostname.
func DefaultName() string {
	h, err := os.Hostname()
	if err != nil {
		return "node"
	}
	name := strings.Trim(invalidName.ReplaceAllString(strings.ToLower(h), "-"), "-.")
	if name == "" {
		return "node"
	}
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}

// Load reads and validates the configuration.
func Load(l *config.Loader) (Config, error) {
	cfg := Config{
		CloudURL:     l.URL("PF_AGENT_CLOUD_URL").String(),
		JoinToken:    l.String("PF_AGENT_JOIN_TOKEN", ""),
		Name:         l.String("PF_AGENT_NAME", DefaultName()),
		DataDir:      l.String("PF_AGENT_DATA_DIR", "/var/lib/parallelf/cloud"),
		LibvirtURI:   l.String("PF_AGENT_LIBVIRT_URI", "qemu:///system"),
		DockerSocket: l.String("PF_AGENT_DOCKER_SOCKET", "/var/run/docker.sock"),
		EnableVMs:    l.Bool("PF_AGENT_ENABLE_VMS", true),
		// The Docker daemon also runs the platform itself on a
		// development machine; ParallelF only touches labelled objects.
		EnableContainers: l.Bool("PF_AGENT_ENABLE_CONTAINERS", true),
		// Held back for the host OS, the editor and the platform services.
		ReservedCPUs:      l.Int("PF_AGENT_RESERVED_CPUS", 1, 0, 1024),
		ReservedMemoryMiB: l.Int("PF_AGENT_RESERVED_MEMORY_MIB", 4096, 0, 1<<24),
		ReservedDiskGiB:   l.Int("PF_AGENT_RESERVED_DISK_GIB", 20, 0, 1<<20),
		LogLevel:          l.OneOf("PF_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
	}
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`).MatchString(cfg.Name) {
		l.Invalid("PF_AGENT_NAME", "must be lower-case letters, digits, dots and hyphens")
	}
	if !strings.HasPrefix(cfg.DataDir, "/") {
		l.Invalid("PF_AGENT_DATA_DIR", "must be an absolute path")
	}
	return cfg, l.Err()
}
