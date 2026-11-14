// Package cloudagent defines the protocol between pf-cloudd and
// pf-node-agent.
//
// The protocol is level-triggered (ADR-0006): on every sync the agent
// reports what it observes on its host and receives the complete desired
// state for that host. A lost or repeated message only delays convergence;
// it can never leave a host half-configured, because the next sync carries
// the whole picture again.
//
//	POST /agent/v1/register   join token -> node id + node credential
//	POST /agent/v1/sync       observed state -> desired state
//
// Both endpoints are served by pf-cloudd on its internal port and are not
// routed through pf-gateway: agents authenticate with node credentials,
// not user tokens.
package cloudagent

import "time"

// Header carrying the protocol version; pf-cloudd rejects other versions.
const (
	VersionHeader = "X-PF-Agent-Protocol"
	Version       = "1"
)

// Workload kinds.
const (
	KindVM        = "vm"
	KindContainer = "container"
)

// Network kinds.
const (
	NetworkNAT      = "nat"      // outbound internet through the host
	NetworkIsolated = "isolated" // no route off the network; host has an address
	NetworkLab      = "lab"      // isolated, and the host has no address either
)

// Desired power states sent to the agent.
const (
	PowerRunning = "running"
	PowerStopped = "stopped"
	PowerAbsent  = "absent" // delete the workload and everything it owns
)

// Observed workload states reported by the agent.
const (
	ObservedProvisioning = "provisioning" // being created or started
	ObservedRunning      = "running"      // running and reachable
	ObservedStopping     = "stopping"
	ObservedStopped      = "stopped"
	ObservedAbsent       = "absent" // does not exist on the host
	ObservedError        = "error"  // provisioning failed; Message says why
)

// RegisterRequest is sent with the cluster join token as bearer credential.
type RegisterRequest struct {
	Name         string   `json:"name"`
	AgentVersion string   `json:"agent_version"`
	Node         NodeInfo `json:"node"`
}

// RegisterResponse carries the node's own credential. It is shown once;
// pf-cloudd stores only its hash.
type RegisterResponse struct {
	NodeID string `json:"node_id"`
	Token  string `json:"token"`
}

// NodeInfo describes a host's capabilities and capacity.
type NodeInfo struct {
	KVM               bool   `json:"kvm"`
	Docker            bool   `json:"docker"`
	Hypervisor        string `json:"hypervisor,omitempty"` // e.g. "libvirt 10.0.0"
	CPUCount          int    `json:"cpu_count"`
	MemoryMiB         int64  `json:"memory_mib"`
	DiskGiB           int64  `json:"disk_gib"`
	ReservedCPUs      int    `json:"reserved_cpus"`
	ReservedMemoryMiB int64  `json:"reserved_memory_mib"`
	ReservedDiskGiB   int64  `json:"reserved_disk_gib"`
}

// NodeMetrics is one utilisation sample of the whole host.
type NodeMetrics struct {
	At             time.Time `json:"at"`
	CPUPercent     float64   `json:"cpu_percent"`
	MemoryUsedMiB  int64     `json:"memory_used_mib"`
	MemoryTotalMiB int64     `json:"memory_total_mib"`
	DiskUsedGiB    float64   `json:"disk_used_gib"`
	DiskTotalGiB   float64   `json:"disk_total_gib"`
}

// SyncRequest reports the agent's view of its host.
type SyncRequest struct {
	AgentVersion string             `json:"agent_version"`
	Node         NodeInfo           `json:"node"`
	Workloads    []ObservedWorkload `json:"workloads"`
	// Metrics is set when a new sample was taken since the last sync.
	Metrics *NodeMetrics `json:"metrics,omitempty"`
}

// ObservedWorkload is the agent's report about one workload it was told about
// or found on the host.
type ObservedWorkload struct {
	ID string `json:"id"`
	// AppliedGeneration is the newest desired generation the agent has fully
	// applied. Zero when it has not applied any yet.
	AppliedGeneration int64  `json:"applied_generation"`
	State             string `json:"state"`
	Message           string `json:"message,omitempty"`
	// Usage is set when the workload is running and a sample was taken.
	CPUPercent    *float64 `json:"cpu_percent,omitempty"`
	MemoryUsedMiB *int64   `json:"memory_used_mib,omitempty"`
}

// SyncResponse is the complete desired state of the host.
type SyncResponse struct {
	NodeID    string            `json:"node_id"`
	Networks  []DesiredNetwork  `json:"networks"`
	Workloads []DesiredWorkload `json:"workloads"`
	// Next sync no later than this many seconds from now.
	SyncIntervalSeconds int `json:"sync_interval_seconds"`
}

// DesiredNetwork is a network that must exist on the host because at least
// one of its workloads uses it.
type DesiredNetwork struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Bridge string `json:"bridge"` // Linux interface name, at most 15 bytes
	CIDR   string `json:"cidr"`   // e.g. 10.20.1.0/24
	// Gateway is the host's address on the network; empty for lab networks.
	Gateway string `json:"gateway,omitempty"`
	// DHCPSpare is the small range handed to unknown MAC addresses. Known
	// workloads always get their reserved address. Empty for lab networks.
	DHCPSpareStart string `json:"dhcp_spare_start,omitempty"`
	DHCPSpareEnd   string `json:"dhcp_spare_end,omitempty"`
	// Reservations maps every VM on this host and network to its address.
	Reservations []DHCPReservation `json:"reservations"`
}

// DHCPReservation binds a MAC address to an IP address.
type DHCPReservation struct {
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
	Name string `json:"name"`
}

// DesiredWorkload is one workload the host must converge to.
type DesiredWorkload struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Generation int64  `json:"generation"`
	Power      string `json:"power"`
	VCPUs      int    `json:"vcpus"`
	MemoryMiB  int    `json:"memory_mib"`
	DiskGiB    int    `json:"disk_gib"`
	Image      Image  `json:"image"`
	NetworkID  string `json:"network_id"`
	IP         string `json:"ip"`
	PrefixLen  int    `json:"prefix_len"`
	MAC        string `json:"mac"`
	// VM only: the NoCloud seed (cloud-init) documents, rendered by pf-cloudd.
	CloudInit *CloudInit `json:"cloud_init,omitempty"`
	// Container only.
	Container *ContainerSpec `json:"container,omitempty"`
}

// Image identifies what a workload boots from.
type Image struct {
	// Source is an https URL (VM) or an OCI reference (container).
	Source string `json:"source"`
	// SHA256 is required for VM images and checked before first use.
	SHA256 string `json:"sha256,omitempty"`
}

// CloudInit holds the three NoCloud seed files.
type CloudInit struct {
	MetaData      string `json:"meta_data"`
	UserData      string `json:"user_data"`
	NetworkConfig string `json:"network_config,omitempty"`
}

// ContainerSpec configures a container workload.
type ContainerSpec struct {
	Command []string          `json:"command,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	CapAdd  []string          `json:"cap_add,omitempty"`
}
