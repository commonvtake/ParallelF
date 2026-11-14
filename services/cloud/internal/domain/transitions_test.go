package domain

import (
	"testing"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
)

func TestObserve(t *testing.T) {
	obs := func(state string, applied int64, msg string) *cloudagent.ObservedWorkload {
		return &cloudagent.ObservedWorkload{State: state, AppliedGeneration: applied, Message: msg}
	}
	cases := []struct {
		name    string
		desired string
		current string
		gen     int64
		obs     *cloudagent.ObservedWorkload
		want    string
		wantMsg string
		wantGen int64
	}{
		{"no report keeps state", DesiredRunning, StateScheduled, 1, nil, StateScheduled, "", 0},
		{"absent while scheduled stays scheduled", DesiredRunning, StateScheduled, 1, obs("absent", 0, ""), StateScheduled, "", 0},
		{"agent starts provisioning", DesiredRunning, StateScheduled, 1, obs("provisioning", 0, "downloading image"), StateProvisioning, "downloading image", 0},
		{"running at the current generation", DesiredRunning, StateProvisioning, 1, obs("running", 1, ""), StateRunning, "", 1},
		{"running at an old generation is not done", DesiredRunning, StateStopped, 3, obs("running", 2, ""), StateProvisioning, "", 2},
		{"provisioning failure", DesiredRunning, StateProvisioning, 1, obs("error", 0, "image checksum mismatch"), StateError, "image checksum mismatch", 0},
		{"stopped while it should run is progress", DesiredRunning, StateStopped, 3, obs("stopped", 2, ""), StateProvisioning, "", 2},
		{"stop requested, still running", DesiredStopped, StateRunning, 2, obs("running", 1, ""), StateStopping, "", 1},
		{"stopped at the current generation", DesiredStopped, StateStopping, 2, obs("stopped", 2, ""), StateStopped, "", 2},
		{"stopped before applying the new generation", DesiredStopped, StateStopping, 2, obs("stopped", 1, ""), StateStopping, "", 1},
		{"delete in progress", DesiredDeleted, StateDeleting, 3, obs("stopping", 2, ""), StateDeleting, "", 2},
		{"delete finished", DesiredDeleted, StateDeleting, 3, obs("absent", 3, ""), StateDeleted, "", 3},
		{"observed generation never goes backwards", DesiredRunning, StateRunning, 4, obs("running", 2, ""), StateProvisioning, "", 4},
		{"a failure of an older generation does not undo a retry", DesiredRunning, StateScheduled, 3,
			&cloudagent.ObservedWorkload{State: "error", Generation: 2, AppliedGeneration: 1, Message: "image checksum mismatch"},
			StateScheduled, "", 1},
		{"a failure of the current generation counts", DesiredRunning, StateProvisioning, 3,
			&cloudagent.ObservedWorkload{State: "error", Generation: 3, AppliedGeneration: 1, Message: "image checksum mismatch"},
			StateError, "image checksum mismatch", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := Workload{DesiredState: tc.desired, State: tc.current, Generation: tc.gen}
			if tc.name == "observed generation never goes backwards" {
				w.ObservedGeneration = 4
			}
			got := Observe(w, tc.obs)
			if got.State != tc.want || got.Message != tc.wantMsg || got.ObservedGeneration != tc.wantGen {
				t.Errorf("Observe = %+v, want state %s msg %q gen %d", got, tc.want, tc.wantMsg, tc.wantGen)
			}
		})
	}
}

func TestPowerActionsNeedANodeAndAllowedState(t *testing.T) {
	onNode := func(desired, state string) Workload {
		return Workload{NodeID: "n1", DesiredState: desired, State: state}
	}
	if CanStart(Workload{DesiredState: DesiredStopped, State: StateStopped}) {
		t.Error("start allowed without a node")
	}
	if !CanStart(onNode(DesiredStopped, StateStopped)) || !CanStart(onNode(DesiredRunning, StateError)) {
		t.Error("start refused for a stopped or failed workload")
	}
	if CanStart(onNode(DesiredRunning, StateRunning)) || CanStart(onNode(DesiredDeleted, StateDeleting)) {
		t.Error("start allowed for a running or deleting workload")
	}
	if !CanStop(onNode(DesiredRunning, StateRunning)) || !CanStop(onNode(DesiredRunning, StateProvisioning)) {
		t.Error("stop refused for a running workload")
	}
	if CanStop(onNode(DesiredStopped, StateStopped)) || CanStop(onNode(DesiredDeleted, StateDeleting)) {
		t.Error("stop allowed for a stopped or deleting workload")
	}
}

func TestQuotaViolations(t *testing.T) {
	q := Quota{MaxVCPUs: 4, MaxMemoryMiB: 4096, MaxDiskGiB: 40, MaxWorkloads: 3}
	if v := QuotaViolations(q, Usage{VCPUs: 2, MemoryMiB: 2048, DiskGiB: 20, Workloads: 2}, Resources{VCPUs: 2, MemoryMiB: 2048, DiskGiB: 20}); len(v) != 0 {
		t.Errorf("exact fit rejected: %v", v)
	}
	v := QuotaViolations(q, Usage{VCPUs: 4, MemoryMiB: 4000, DiskGiB: 1, Workloads: 3}, Resources{VCPUs: 1, MemoryMiB: 512, DiskGiB: 1})
	want := []string{"workloads", "vcpus", "memory_mib"}
	if len(v) != len(want) {
		t.Fatalf("violations = %v, want %v", v, want)
	}
	for i := range want {
		if v[i] != want[i] {
			t.Fatalf("violations = %v, want %v", v, want)
		}
	}
}

func TestAllocatableHonoursReservationsAndOvercommit(t *testing.T) {
	n := Node{CPUCount: 12, MemoryMiB: 16000, DiskGiB: 200, ReservedCPUs: 2, ReservedMemoryMiB: 4000, ReservedDiskGiB: 20}
	got := n.AllocatableResources(DefaultOvercommit)
	want := Resources{VCPUs: 40, MemoryMiB: 12000, DiskGiB: 180}
	if got != want {
		t.Errorf("AllocatableResources = %+v, want %+v", got, want)
	}
	if !(Resources{VCPUs: 40, MemoryMiB: 12000, DiskGiB: 180}).Fits(want) || (Resources{MemoryMiB: 12001}).Fits(want) {
		t.Error("Fits is wrong at the boundary")
	}
	tiny := Node{CPUCount: 1, MemoryMiB: 1000, ReservedCPUs: 2, ReservedMemoryMiB: 4000}
	if got := tiny.AllocatableResources(DefaultOvercommit); got.VCPUs != 0 || got.MemoryMiB != 0 {
		t.Errorf("reservation larger than the host gave %+v", got)
	}
}
