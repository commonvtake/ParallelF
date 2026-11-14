// Package scheduler chooses a compute node for a workload.
//
// It is a pure function over a snapshot of the nodes: the store takes row
// locks on every candidate node, computes their allocations, calls Choose,
// and commits the binding in the same transaction, so two placements can
// never claim the same capacity.
package scheduler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
)

// Candidate is a node with the resources already reserved on it.
type Candidate struct {
	Node      domain.Node
	Allocated domain.Resources
}

// Request describes what has to be placed.
type Request struct {
	Kind      string // domain.KindVM or domain.KindContainer
	Resources domain.Resources
}

// Result is the outcome of a scheduling attempt.
type Result struct {
	NodeID string
	// Reason explains why nothing fits, e.g.
	// "0/1 nodes available: 1 insufficient memory". Empty on success.
	Reason string
}

// Choose filters out nodes that cannot run the workload and picks the one
// that leaves the least free memory afterwards (bin packing). Packing keeps
// whole hosts free on a memory-constrained workstation. Ties go to the node
// with the lowest id, so the result is deterministic.
func Choose(candidates []Candidate, req Request, oc domain.Overcommit) Result {
	reasons := map[string]int{}
	type fit struct {
		id       string
		freeMem  int64
		freeCPUs int
	}
	var fits []fit

	for _, c := range candidates {
		if reason := filter(c, req, oc); reason != "" {
			reasons[reason]++
			continue
		}
		free := c.Node.AllocatableResources(oc).Sub(c.Allocated).Sub(req.Resources)
		fits = append(fits, fit{id: c.Node.ID, freeMem: free.MemoryMiB, freeCPUs: free.VCPUs})
	}

	if len(fits) == 0 {
		return Result{Reason: describe(len(candidates), reasons)}
	}
	sort.Slice(fits, func(i, j int) bool {
		if fits[i].freeMem != fits[j].freeMem {
			return fits[i].freeMem < fits[j].freeMem
		}
		if fits[i].freeCPUs != fits[j].freeCPUs {
			return fits[i].freeCPUs < fits[j].freeCPUs
		}
		return fits[i].id < fits[j].id
	})
	return Result{NodeID: fits[0].id}
}

// filter returns why c cannot take req, or "" when it can.
func filter(c Candidate, req Request, oc domain.Overcommit) string {
	n := c.Node
	switch {
	case n.Status != domain.NodeReady:
		return "not ready"
	case !n.Schedulable:
		return "cordoned"
	case req.Kind == domain.KindVM && !n.KVM:
		return "no KVM"
	case req.Kind == domain.KindContainer && !n.Docker:
		return "no Docker"
	}
	free := n.AllocatableResources(oc).Sub(c.Allocated)
	switch {
	case req.Resources.MemoryMiB > free.MemoryMiB:
		return "insufficient memory"
	case req.Resources.VCPUs > free.VCPUs:
		return "insufficient CPU"
	case req.Resources.DiskGiB > free.DiskGiB:
		return "insufficient disk"
	}
	return ""
}

func describe(total int, reasons map[string]int) string {
	if total == 0 {
		return "no compute nodes are registered"
	}
	keys := make([]string, 0, len(reasons))
	for k := range reasons {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", reasons[k], k))
	}
	return fmt.Sprintf("0/%d nodes available: %s", total, strings.Join(parts, ", "))
}
