// Package runtime defines what the agent needs from a workload runtime
// (libvirt for VMs, Docker for containers).
package runtime

import (
	"context"
	"errors"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
)

// ErrUnavailable means the runtime cannot be used on this host.
var ErrUnavailable = errors.New("runtime unavailable")

// Instance is a workload as it exists on the host.
type Instance struct {
	ID      string
	Running bool
}

// Usage is one utilisation sample of an instance.
type Usage struct {
	// CPUPercent is relative to the workload's own vCPUs (100 = all busy).
	CPUPercent    float64
	MemoryUsedMiB int64
}

// Progress reports a human-readable step ("downloading image 40%").
type Progress func(message string)

// Runtime manages one kind of workload. Every method is idempotent and
// touches only resources the runtime labelled as ParallelF-managed.
type Runtime interface {
	// Kind is cloudagent.KindVM or cloudagent.KindContainer.
	Kind() string
	// Probe reports whether the runtime works, and a version string.
	Probe(ctx context.Context) (version string, err error)

	// SyncNetworks creates or updates every desired network and removes
	// the managed networks whose ids are in remove.
	SyncNetworks(ctx context.Context, desired []cloudagent.DesiredNetwork, remove []string) error
	// ListNetworks returns the bridge names of managed networks.
	ListNetworks(ctx context.Context) ([]string, error)

	// List returns every managed instance by workload id.
	List(ctx context.Context) (map[string]Instance, error)
	// Create makes the instance exist (stopped) as described.
	Create(ctx context.Context, w cloudagent.DesiredWorkload, network cloudagent.DesiredNetwork, progress Progress) error
	Start(ctx context.Context, id string) error
	// Stop asks the instance to shut down and may return before it has.
	Stop(ctx context.Context, id string) error
	// Kill powers the instance off immediately.
	Kill(ctx context.Context, id string) error
	// Delete removes the instance and everything it owns on the host.
	Delete(ctx context.Context, id string) error
	// Usage samples a running instance; ok is false when no sample exists.
	Usage(ctx context.Context, id string, vcpus int) (u Usage, ok bool)
}
