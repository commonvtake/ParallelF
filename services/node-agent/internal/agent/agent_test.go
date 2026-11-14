package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
	"github.com/commonvtake/parallelf/services/node-agent/internal/runtime"
)

type fakeRuntime struct {
	mu        sync.Mutex
	kind      string
	instances map[string]runtime.Instance
	networks  map[string]bool
	createErr error
	calls     []string
	synced    [][]string
}

func newFake(kind string) *fakeRuntime {
	return &fakeRuntime{kind: kind, instances: map[string]runtime.Instance{}, networks: map[string]bool{}}
}

func (f *fakeRuntime) record(c string) { f.calls = append(f.calls, c) }

func (f *fakeRuntime) Kind() string                          { return f.kind }
func (f *fakeRuntime) Probe(context.Context) (string, error) { return "fake", nil }
func (f *fakeRuntime) ListNetworks(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for n := range f.networks {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func (f *fakeRuntime) SyncNetworks(_ context.Context, desired []cloudagent.DesiredNetwork, remove []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var names []string
	for _, n := range desired {
		f.networks[n.Bridge] = true
		names = append(names, n.Bridge)
	}
	for _, n := range remove {
		delete(f.networks, n)
		f.record("remove-network " + n)
	}
	f.synced = append(f.synced, names)
	return nil
}

func (f *fakeRuntime) List(context.Context) (map[string]runtime.Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]runtime.Instance{}
	for k, v := range f.instances {
		out[k] = v
	}
	return out, nil
}

func (f *fakeRuntime) Create(_ context.Context, w cloudagent.DesiredWorkload, _ cloudagent.DesiredNetwork, p runtime.Progress) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("create " + w.ID)
	if f.createErr != nil {
		return f.createErr
	}
	p("downloading image")
	f.instances[w.ID] = runtime.Instance{ID: w.ID}
	return nil
}

func (f *fakeRuntime) set(id string, running bool, op string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record(op + " " + id)
	inst, ok := f.instances[id]
	if !ok {
		return errors.New("no such instance")
	}
	inst.Running = running
	f.instances[id] = inst
	return nil
}

func (f *fakeRuntime) Start(_ context.Context, id string) error { return f.set(id, true, "start") }
func (f *fakeRuntime) Stop(_ context.Context, id string) error  { return f.set(id, false, "stop") }
func (f *fakeRuntime) Kill(_ context.Context, id string) error  { return f.set(id, false, "kill") }

func (f *fakeRuntime) Delete(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("delete " + id)
	delete(f.instances, id)
	return nil
}

func (f *fakeRuntime) Usage(context.Context, string, int) (runtime.Usage, bool) {
	return runtime.Usage{CPUPercent: 12.5, MemoryUsedMiB: 100}, true
}

func (f *fakeRuntime) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newAgent(t *testing.T, rts ...runtime.Runtime) (*Agent, *clock) {
	t.Helper()
	a, err := New(t.TempDir(), rts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}
	a.now = c.now
	return a, c
}

func vm(id, power string, gen int64) cloudagent.DesiredWorkload {
	return cloudagent.DesiredWorkload{ID: id, Kind: cloudagent.KindVM, Power: power, Generation: gen, NetworkID: "n1", VCPUs: 1}
}

func desired(ws ...cloudagent.DesiredWorkload) cloudagent.SyncResponse {
	return cloudagent.SyncResponse{
		Networks:  []cloudagent.DesiredNetwork{{ID: "n1", Bridge: "pfbr-00000001", Kind: "nat"}},
		Workloads: ws,
	}
}

// settle runs reconcile passes until no worker is busy.
func settle(t *testing.T, a *Agent) {
	t.Helper()
	for i := 0; i < 200; i++ {
		a.Reconcile(context.Background())
		a.wg.Wait()
		a.mu.Lock()
		busy := false
		for _, ws := range a.workers {
			busy = busy || ws.busy
		}
		a.mu.Unlock()
		if !busy {
			a.Reconcile(context.Background())
			a.wg.Wait()
			return
		}
	}
	t.Fatal("workers never settled")
}

func observed(a *Agent, id string) cloudagent.ObservedWorkload {
	for _, o := range a.Observe(context.Background()) {
		if o.ID == id {
			return o
		}
	}
	return cloudagent.ObservedWorkload{}
}

func TestCreatesStartsAndReportsRunning(t *testing.T) {
	rt := newFake(cloudagent.KindVM)
	a, _ := newAgent(t, rt)
	a.SetDesired(desired(vm("w1", cloudagent.PowerRunning, 1)))

	if o := observed(a, "w1"); o.State != cloudagent.ObservedAbsent {
		t.Fatalf("before reconcile: %+v", o)
	}
	settle(t, a)

	o := observed(a, "w1")
	if o.State != cloudagent.ObservedRunning || o.AppliedGeneration != 1 || o.CPUPercent == nil {
		t.Fatalf("observed %+v", o)
	}
	if got := rt.callList(); len(got) != 2 || got[0] != "create w1" || got[1] != "start w1" {
		t.Fatalf("calls %v", got)
	}
	if len(rt.synced) == 0 || len(rt.synced[0]) != 1 || rt.synced[0][0] != "pfbr-00000001" {
		t.Fatalf("network not ensured: %v", rt.synced)
	}
}

func TestAlreadyConvergedNeedsNoWork(t *testing.T) {
	rt := newFake(cloudagent.KindVM)
	rt.instances["w1"] = runtime.Instance{ID: "w1", Running: true}
	a, _ := newAgent(t, rt)
	a.SetDesired(desired(vm("w1", cloudagent.PowerRunning, 4)))
	settle(t, a)

	if o := observed(a, "w1"); o.AppliedGeneration != 4 || o.State != cloudagent.ObservedRunning {
		t.Fatalf("observed %+v", o)
	}
	if calls := rt.callList(); len(calls) != 0 {
		t.Fatalf("no work expected, got %v", calls)
	}
}

func TestAppliedGenerationSurvivesRestart(t *testing.T) {
	rt := newFake(cloudagent.KindVM)
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, _ := New(dir, []runtime.Runtime{rt}, logger)
	a.SetDesired(desired(vm("w1", cloudagent.PowerRunning, 2)))
	settle(t, a)

	b, err := New(dir, []runtime.Runtime{rt}, logger)
	if err != nil {
		t.Fatal(err)
	}
	b.SetDesired(desired(vm("w1", cloudagent.PowerRunning, 2)))
	if o := observed(b, "w1"); o.AppliedGeneration != 2 || o.State != cloudagent.ObservedRunning {
		t.Fatalf("after restart: %+v", o)
	}
}

func TestFailuresAreRetriedThenReported(t *testing.T) {
	rt := newFake(cloudagent.KindVM)
	rt.createErr = errors.New("image checksum mismatch")
	a, clk := newAgent(t, rt)
	a.SetDesired(desired(vm("w1", cloudagent.PowerRunning, 1)))

	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		a.Reconcile(context.Background())
		a.wg.Wait()
		o := observed(a, "w1")
		if attempt < MaxAttempts && (o.State != cloudagent.ObservedAbsent || o.Message == "") {
			t.Fatalf("attempt %d: %+v", attempt, o)
		}
		// Before the backoff expires nothing is retried.
		a.Reconcile(context.Background())
		a.wg.Wait()
		clk.add(time.Minute)
	}
	o := observed(a, "w1")
	if o.State != cloudagent.ObservedError || o.Message != "image checksum mismatch" {
		t.Fatalf("after %d attempts: %+v", MaxAttempts, o)
	}
	creates := 0
	for _, c := range rt.callList() {
		if c == "create w1" {
			creates++
		}
	}
	if creates != MaxAttempts {
		t.Fatalf("created %d times, want %d", creates, MaxAttempts)
	}

	// A new generation (the user's retry) starts over and can succeed.
	rt.mu.Lock()
	rt.createErr = nil
	rt.mu.Unlock()
	a.SetDesired(desired(vm("w1", cloudagent.PowerRunning, 2)))
	settle(t, a)
	if o := observed(a, "w1"); o.State != cloudagent.ObservedRunning || o.AppliedGeneration != 2 {
		t.Fatalf("after retry: %+v", o)
	}
}

func TestStopAndDelete(t *testing.T) {
	rt := newFake(cloudagent.KindVM)
	rt.instances["w1"] = runtime.Instance{ID: "w1", Running: true}
	a, _ := newAgent(t, rt)

	a.SetDesired(desired(vm("w1", cloudagent.PowerStopped, 2)))
	settle(t, a)
	if o := observed(a, "w1"); o.State != cloudagent.ObservedStopped || o.AppliedGeneration != 2 {
		t.Fatalf("stopped: %+v", o)
	}

	a.SetDesired(desired(vm("w1", cloudagent.PowerAbsent, 3)))
	settle(t, a)
	if o := observed(a, "w1"); o.State != cloudagent.ObservedAbsent || o.AppliedGeneration != 3 {
		t.Fatalf("deleted: %+v", o)
	}
	calls := rt.callList()
	if calls[0] != "stop w1" || calls[len(calls)-1] != "delete w1" {
		t.Fatalf("calls %v", calls)
	}
}

func TestOrphansAreRemovedOnlyAfterGraceAndWithFreshDesiredState(t *testing.T) {
	rt := newFake(cloudagent.KindVM)
	rt.instances["orphan"] = runtime.Instance{ID: "orphan", Running: true}
	a, clk := newAgent(t, rt)

	// No desired state yet: nothing happens at all.
	a.Reconcile(context.Background())
	if len(rt.callList()) != 0 {
		t.Fatal("must not act before the first desired state")
	}

	a.SetDesired(desired())
	a.Reconcile(context.Background())
	clk.add(OrphanGrace - time.Second)
	a.SetDesired(desired())
	a.Reconcile(context.Background())
	if len(rt.callList()) != 0 {
		t.Fatalf("removed before the grace period: %v", rt.callList())
	}

	// Desired state is stale (control plane unreachable): still nothing.
	clk.add(DesiredMaxAge + time.Second)
	a.Reconcile(context.Background())
	if len(rt.callList()) != 0 {
		t.Fatalf("removed with stale desired state: %v", rt.callList())
	}

	a.SetDesired(desired())
	a.Reconcile(context.Background())
	calls := rt.callList()
	if len(calls) != 2 || calls[0] != "kill orphan" || calls[1] != "delete orphan" {
		t.Fatalf("calls %v", calls)
	}
}

func TestUnusedNetworksAreRemovedAfterGrace(t *testing.T) {
	rt := newFake(cloudagent.KindVM)
	rt.networks["pfbr-old00000"] = true
	a, clk := newAgent(t, rt)

	a.SetDesired(desired(vm("w1", cloudagent.PowerStopped, 1)))
	a.Reconcile(context.Background())
	clk.add(NetworkGrace)
	a.SetDesired(desired(vm("w1", cloudagent.PowerStopped, 1)))
	a.Reconcile(context.Background())

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.networks["pfbr-old00000"] || !rt.networks["pfbr-00000001"] {
		t.Fatalf("networks %v", rt.networks)
	}
}

func TestUnsupportedKindIsReportedAsError(t *testing.T) {
	a, _ := newAgent(t, newFake(cloudagent.KindVM))
	w := vm("c1", cloudagent.PowerRunning, 1)
	w.Kind = cloudagent.KindContainer
	a.SetDesired(desired(w))
	settle(t, a)

	if o := observed(a, "c1"); o.State != cloudagent.ObservedError {
		t.Fatalf("observed %+v", o)
	}
}
