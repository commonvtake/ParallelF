package scheduler

import (
	"testing"

	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
)

func node(id string, cpus int, memMiB int64, opts ...func(*domain.Node)) domain.Node {
	n := domain.Node{
		ID: id, Status: domain.NodeReady, Schedulable: true, KVM: true, Docker: true,
		CPUCount: cpus, MemoryMiB: memMiB, DiskGiB: 100,
	}
	for _, o := range opts {
		o(&n)
	}
	return n
}

var small = Request{Kind: domain.KindVM, Resources: domain.Resources{VCPUs: 1, MemoryMiB: 1024, DiskGiB: 10}}

func TestChoosePacksOntoTheFullestNode(t *testing.T) {
	got := Choose([]Candidate{
		{Node: node("a", 4, 8192)},
		{Node: node("b", 4, 8192), Allocated: domain.Resources{VCPUs: 2, MemoryMiB: 6144}},
		{Node: node("c", 4, 8192), Allocated: domain.Resources{VCPUs: 1, MemoryMiB: 2048}},
	}, small, domain.DefaultOvercommit)

	if got.NodeID != "b" || got.Reason != "" {
		t.Fatalf("got %+v, want node b", got)
	}
}

func TestChooseIsDeterministicOnTies(t *testing.T) {
	got := Choose([]Candidate{{Node: node("b", 4, 8192)}, {Node: node("a", 4, 8192)}}, small, domain.DefaultOvercommit)
	if got.NodeID != "a" {
		t.Fatalf("got %q, want a", got.NodeID)
	}
}

func TestChooseRespectsReservedResources(t *testing.T) {
	n := node("a", 2, 4096, func(n *domain.Node) { n.ReservedMemoryMiB = 3584 })
	got := Choose([]Candidate{{Node: n}}, small, domain.DefaultOvercommit)

	if got.NodeID != "" || got.Reason != "0/1 nodes available: 1 insufficient memory" {
		t.Fatalf("got %+v", got)
	}
}

func TestChooseAllowsCPUOvercommitButNotMemory(t *testing.T) {
	n := node("a", 1, 2048)
	cpuHeavy := Request{Kind: domain.KindVM, Resources: domain.Resources{VCPUs: 4, MemoryMiB: 512, DiskGiB: 1}}
	if got := Choose([]Candidate{{Node: n}}, cpuHeavy, domain.DefaultOvercommit); got.NodeID != "a" {
		t.Fatalf("4 vCPUs on 1 CPU with 4x overcommit should fit: %+v", got)
	}
	memHeavy := Request{Kind: domain.KindVM, Resources: domain.Resources{VCPUs: 1, MemoryMiB: 4096, DiskGiB: 1}}
	if got := Choose([]Candidate{{Node: n}}, memHeavy, domain.DefaultOvercommit); got.NodeID != "" {
		t.Fatalf("memory must not be overcommitted: %+v", got)
	}
}

func TestChooseFiltersAndExplains(t *testing.T) {
	cands := []Candidate{
		{Node: node("a", 4, 8192, func(n *domain.Node) { n.Status = domain.NodeNotReady })},
		{Node: node("b", 4, 8192, func(n *domain.Node) { n.Schedulable = false })},
		{Node: node("c", 4, 8192, func(n *domain.Node) { n.KVM = false })},
		{Node: node("d", 4, 8192), Allocated: domain.Resources{MemoryMiB: 8000}},
	}
	got := Choose(cands, small, domain.DefaultOvercommit)

	want := "0/4 nodes available: 1 cordoned, 1 insufficient memory, 1 no KVM, 1 not ready"
	if got.NodeID != "" || got.Reason != want {
		t.Fatalf("got %+v, want reason %q", got, want)
	}
}

func TestContainersNeedDocker(t *testing.T) {
	req := Request{Kind: domain.KindContainer, Resources: domain.Resources{VCPUs: 1, MemoryMiB: 128, DiskGiB: 1}}
	n := node("a", 4, 8192, func(n *domain.Node) { n.Docker = false })

	if got := Choose([]Candidate{{Node: n}}, req, domain.DefaultOvercommit); got.Reason != "0/1 nodes available: 1 no Docker" {
		t.Fatalf("got %+v", got)
	}
}

func TestNoNodes(t *testing.T) {
	if got := Choose(nil, small, domain.DefaultOvercommit); got.Reason != "no compute nodes are registered" {
		t.Fatalf("got %+v", got)
	}
}
