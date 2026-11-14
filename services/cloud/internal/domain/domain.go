// Package domain holds the ParallelF Cloud model: nodes, catalogue,
// networks, workloads, quotas, audit entries, and the rules that relate
// them. It has no I/O.
package domain

import (
	"errors"
	"time"
)

// Errors returned by the store and service layers.
var (
	ErrNotFound         = errors.New("not found")
	ErrNameTaken        = errors.New("name already in use")
	ErrCIDROverlap      = errors.New("CIDR overlaps an existing network")
	ErrNetworkInUse     = errors.New("network has workloads")
	ErrNetworkExhausted = errors.New("network has no free address")
	ErrQuotaExceeded    = errors.New("project quota exceeded")
	ErrInvalidState     = errors.New("operation not allowed in the current state")
	ErrNodeActive       = errors.New("node is still reporting")
	ErrUnauthorizedNode = errors.New("unknown node or invalid node credential")
)

// Workload kinds.
const (
	KindVM        = "vm"
	KindContainer = "container"
)

// Desired states.
const (
	DesiredRunning = "running"
	DesiredStopped = "stopped"
	DesiredDeleted = "deleted"
)

// Workload states.
const (
	StatePending      = "PENDING"      // admitted, waiting for a node
	StateScheduled    = "SCHEDULED"    // bound to a node, agent has not started it
	StateProvisioning = "PROVISIONING" // agent is creating or starting it
	StateRunning      = "RUNNING"
	StateStopping     = "STOPPING"
	StateStopped      = "STOPPED"
	StateUnknown      = "UNKNOWN" // its node stopped reporting
	StateDeleting     = "DELETING"
	StateDeleted      = "DELETED"
	StateError        = "ERROR"
)

// Node statuses.
const (
	NodeReady    = "READY"
	NodeNotReady = "NOT_READY"
)

// Node is a compute host running pf-node-agent.
type Node struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Status            string    `json:"status"`
	Schedulable       bool      `json:"schedulable"`
	AgentVersion      string    `json:"agent_version"`
	KVM               bool      `json:"kvm"`
	Docker            bool      `json:"docker"`
	Hypervisor        string    `json:"hypervisor"`
	CPUCount          int       `json:"cpu_count"`
	MemoryMiB         int64     `json:"memory_mib"`
	DiskGiB           int64     `json:"disk_gib"`
	ReservedCPUs      int       `json:"reserved_cpus"`
	ReservedMemoryMiB int64     `json:"reserved_memory_mib"`
	ReservedDiskGiB   int64     `json:"reserved_disk_gib"`
	RegisteredAt      time.Time `json:"registered_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	// Allocatable and Allocated are computed, not stored.
	Allocatable Resources `json:"allocatable"`
	Allocated   Resources `json:"allocated"`
	Workloads   int       `json:"workloads"`
}

// Resources is an amount of compute.
type Resources struct {
	VCPUs     int   `json:"vcpus"`
	MemoryMiB int64 `json:"memory_mib"`
	DiskGiB   int64 `json:"disk_gib"`
}

// Fits reports whether r fits into free.
func (r Resources) Fits(free Resources) bool {
	return r.VCPUs <= free.VCPUs && r.MemoryMiB <= free.MemoryMiB && r.DiskGiB <= free.DiskGiB
}

// Sub returns r minus o.
func (r Resources) Sub(o Resources) Resources {
	return Resources{VCPUs: r.VCPUs - o.VCPUs, MemoryMiB: r.MemoryMiB - o.MemoryMiB, DiskGiB: r.DiskGiB - o.DiskGiB}
}

// Overcommit sets how far allocations may exceed physical capacity.
type Overcommit struct {
	CPU    float64
	Memory float64
	Disk   float64
}

// DefaultOvercommit allows four vCPUs per physical CPU and no memory or disk
// overcommit. Memory is never overcommitted on a 16 GB workstation.
var DefaultOvercommit = Overcommit{CPU: 4, Memory: 1, Disk: 1}

// AllocatableResources is what the scheduler may hand out on n.
func (n Node) AllocatableResources(o Overcommit) Resources {
	r := Resources{
		VCPUs:     int(float64(max(n.CPUCount-n.ReservedCPUs, 0)) * o.CPU),
		MemoryMiB: int64(float64(max(n.MemoryMiB-n.ReservedMemoryMiB, 0)) * o.Memory),
		DiskGiB:   int64(float64(max(n.DiskGiB-n.ReservedDiskGiB, 0)) * o.Disk),
	}
	return r
}

// Flavor is a size of workload.
type Flavor struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	VCPUs     int    `json:"vcpus"`
	MemoryMiB int    `json:"memory_mib"`
	DiskGiB   int    `json:"disk_gib"`
}

// Resources returns the flavor's size.
func (f Flavor) Resources() Resources {
	return Resources{VCPUs: f.VCPUs, MemoryMiB: int64(f.MemoryMiB), DiskGiB: int64(f.DiskGiB)}
}

// Image is a VM disk image or a container image.
type Image struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
	SHA256 string `json:"sha256,omitempty"`
	OS     string `json:"os"`
}

// Template is an immutable, versioned provisioning recipe.
type Template struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Version       int            `json:"version"`
	Kind          string         `json:"kind"`
	Description   string         `json:"description"`
	Image         Image          `json:"image"`
	DefaultFlavor Flavor         `json:"default_flavor"`
	CloudConfig   map[string]any `json:"cloud_config,omitempty"`
	StaticNetwork bool           `json:"static_network"`
	Command       []string       `json:"command,omitempty"`
	CapAdd        []string       `json:"cap_add,omitempty"`
	Deprecated    bool           `json:"deprecated"`
}

// Network is a virtual L2 network with one IPv4 subnet.
type Network struct {
	ID         string     `json:"id"`
	ProjectID  string     `json:"project_id"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	CIDR       string     `json:"cidr"`
	GatewayIP  string     `json:"gateway_ip,omitempty"`
	BridgeName string     `json:"bridge_name"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	DeletedAt  *time.Time `json:"deleted_at,omitempty"`
	// Computed.
	Workloads int `json:"workloads"`
	Capacity  int `json:"capacity"`
}

// WorkloadSpec holds the per-workload settings chosen at creation.
type WorkloadSpec struct {
	SSHAuthorizedKeys []string          `json:"ssh_authorized_keys,omitempty"`
	Env               map[string]string `json:"env,omitempty"`
}

// Workload is a VM or container.
type Workload struct {
	ID                 string       `json:"id"`
	ProjectID          string       `json:"project_id"`
	Name               string       `json:"name"`
	Kind               string       `json:"kind"`
	TemplateID         string       `json:"template_id"`
	TemplateName       string       `json:"template"`
	TemplateVersion    int          `json:"template_version"`
	FlavorID           string       `json:"flavor_id"`
	FlavorName         string       `json:"flavor"`
	NetworkID          string       `json:"network_id"`
	NetworkName        string       `json:"network"`
	NodeID             string       `json:"node_id,omitempty"`
	NodeName           string       `json:"node,omitempty"`
	VCPUs              int          `json:"vcpus"`
	MemoryMiB          int          `json:"memory_mib"`
	DiskGiB            int          `json:"disk_gib"`
	IP                 string       `json:"ip"`
	MAC                string       `json:"mac"`
	DesiredState       string       `json:"desired_state"`
	State              string       `json:"state"`
	Generation         int64        `json:"generation"`
	ObservedGeneration int64        `json:"observed_generation"`
	StatusMessage      string       `json:"status_message"`
	Spec               WorkloadSpec `json:"spec"`
	CreatedBy          string       `json:"created_by"`
	CreatedAt          time.Time    `json:"created_at"`
	UpdatedAt          time.Time    `json:"updated_at"`
	StateChangedAt     time.Time    `json:"state_changed_at"`
	DeletedAt          *time.Time   `json:"deleted_at,omitempty"`
}

// Resources returns the workload's reservation.
func (w Workload) Resources() Resources {
	return Resources{VCPUs: w.VCPUs, MemoryMiB: int64(w.MemoryMiB), DiskGiB: int64(w.DiskGiB)}
}

// Converging reports whether the system is still working toward the
// workload's desired state.
func (w Workload) Converging() bool {
	switch w.State {
	case StatePending, StateScheduled, StateProvisioning, StateStopping, StateDeleting:
		return true
	}
	return w.ObservedGeneration < w.Generation && w.State != StateError && w.State != StateDeleted
}

// Quota limits a project's total reservations.
type Quota struct {
	ProjectID    string     `json:"project_id"`
	MaxVCPUs     int        `json:"max_vcpus"`
	MaxMemoryMiB int        `json:"max_memory_mib"`
	MaxDiskGiB   int        `json:"max_disk_gib"`
	MaxWorkloads int        `json:"max_workloads"`
	IsDefault    bool       `json:"is_default"`
	UpdatedBy    string     `json:"updated_by,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
}

// Usage is what a project currently reserves.
type Usage struct {
	VCPUs     int `json:"vcpus"`
	MemoryMiB int `json:"memory_mib"`
	DiskGiB   int `json:"disk_gib"`
	Workloads int `json:"workloads"`
}

// QuotaViolations lists every limit the request would exceed.
func QuotaViolations(q Quota, used Usage, req Resources) []string {
	var out []string
	if used.Workloads+1 > q.MaxWorkloads {
		out = append(out, "workloads")
	}
	if used.VCPUs+req.VCPUs > q.MaxVCPUs {
		out = append(out, "vcpus")
	}
	if int64(used.MemoryMiB)+req.MemoryMiB > int64(q.MaxMemoryMiB) {
		out = append(out, "memory_mib")
	}
	if int64(used.DiskGiB)+req.DiskGiB > int64(q.MaxDiskGiB) {
		out = append(out, "disk_gib")
	}
	return out
}

// WorkloadEvent is one entry of a workload's history.
type WorkloadEvent struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Type    string    `json:"type"`
	Message string    `json:"message"`
}

// Actor identifies who performed an audited action.
type Actor struct {
	Type      string // user, agent or system
	ID        string
	Name      string
	RequestID string
}

// AuditEntry is one row of the audit trail.
type AuditEntry struct {
	Seq          int64             `json:"seq"`
	ID           string            `json:"id"`
	At           time.Time         `json:"at"`
	ActorType    string            `json:"actor_type"`
	ActorID      string            `json:"actor_id"`
	ActorName    string            `json:"actor_name"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	ProjectID    string            `json:"project_id,omitempty"`
	Outcome      string            `json:"outcome"`
	RequestID    string            `json:"request_id"`
	Details      map[string]string `json:"details"`
	PrevHash     string            `json:"prev_hash"`
	Hash         string            `json:"hash"`
}

// MetricPoint is one utilisation sample.
type MetricPoint struct {
	At             time.Time `json:"at"`
	CPUPercent     float64   `json:"cpu_percent"`
	MemoryUsedMiB  int64     `json:"memory_used_mib"`
	MemoryTotalMiB int64     `json:"memory_total_mib,omitempty"`
	DiskUsedGiB    float64   `json:"disk_used_gib,omitempty"`
	DiskTotalGiB   float64   `json:"disk_total_gib,omitempty"`
}

// OutboxEvent is a domain event ready to be written to cloud.outbox.
type OutboxEvent struct {
	ID      string
	Subject string
	Type    string
	Payload []byte
	Headers map[string]string
}
