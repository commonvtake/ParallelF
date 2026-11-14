// Package agent converges a host to the desired state pf-cloudd sends.
//
// The sync loop (see Run) reports observations and receives the complete
// desired state. The reconciler compares it with what the runtimes report
// and starts one worker per workload that needs work. Workers are
// idempotent: a crash or restart at any point is repaired by running them
// again.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
	"github.com/commonvtake/parallelf/services/node-agent/internal/runtime"
)

// Tunables.
const (
	MaxAttempts     = 3                // per generation, then the workload is reported in error
	OrphanGrace     = 2 * time.Minute  // before an unknown managed instance is removed
	NetworkGrace    = 3 * time.Minute  // before an unneeded managed network is removed
	DesiredMaxAge   = 60 * time.Second // older desired state is not trusted for removals
	VMStopTimeout   = 90 * time.Second // ACPI shutdown, then power off
	UsageInterval   = 10 * time.Second
	maxErrorMessage = 300
)

var backoff = []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second}

// workerState tracks one workload's in-flight or failed work.
type workerState struct {
	generation int64
	busy       bool
	cancel     context.CancelFunc
	message    string
	attempts   int
	lastError  string
	retryAt    time.Time
}

// Agent holds desired and observed state. All methods are safe for
// concurrent use.
type Agent struct {
	runtimes map[string]runtime.Runtime // by workload kind
	dataDir  string
	logger   *slog.Logger
	now      func() time.Time

	mu            sync.Mutex
	desired       cloudagent.SyncResponse
	desiredAt     time.Time
	state         persisted
	workers       map[string]*workerState
	orphansSeen   map[string]time.Time
	networksSeen  map[string]time.Time
	usage         map[string]usageSample
	reconcileWake chan struct{}
	reportWake    chan struct{}
	wg            sync.WaitGroup
}

type usageSample struct {
	at    time.Time
	usage runtime.Usage
}

// New creates an agent. Runtimes that failed their probe must not be passed.
func New(dataDir string, runtimes []runtime.Runtime, logger *slog.Logger) (*Agent, error) {
	st, err := loadState(statePath(dataDir))
	if err != nil {
		return nil, err
	}
	a := &Agent{
		runtimes:      map[string]runtime.Runtime{},
		dataDir:       dataDir,
		logger:        logger,
		now:           time.Now,
		state:         st,
		workers:       map[string]*workerState{},
		orphansSeen:   map[string]time.Time{},
		networksSeen:  map[string]time.Time{},
		usage:         map[string]usageSample{},
		reconcileWake: make(chan struct{}, 1),
		reportWake:    make(chan struct{}, 1),
	}
	for _, r := range runtimes {
		a.runtimes[r.Kind()] = r
	}
	return a, nil
}

// ReportWake fires when a worker finished, so the next sync can report it
// without waiting for the interval.
func (a *Agent) ReportWake() <-chan struct{} { return a.reportWake }

func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// SetDesired stores a new desired state and triggers reconciliation.
// Workers busy with an outdated generation are cancelled.
func (a *Agent) SetDesired(resp cloudagent.SyncResponse) {
	a.mu.Lock()
	a.desired = resp
	a.desiredAt = a.now()
	for _, w := range resp.Workloads {
		if ws, ok := a.workers[w.ID]; ok && ws.busy && ws.generation < w.Generation && ws.cancel != nil {
			ws.cancel()
		}
	}
	a.mu.Unlock()
	signal(a.reconcileWake)
}

// Observe reports every desired workload as the host currently has it.
func (a *Agent) Observe(ctx context.Context) []cloudagent.ObservedWorkload {
	a.mu.Lock()
	desired := append([]cloudagent.DesiredWorkload(nil), a.desired.Workloads...)
	a.mu.Unlock()

	instances := a.listAll(ctx)
	out := make([]cloudagent.ObservedWorkload, 0, len(desired))
	for _, w := range desired {
		inst, exists := instances[w.ID]
		obs := cloudagent.ObservedWorkload{ID: w.ID, Generation: w.Generation}

		a.mu.Lock()
		obs.AppliedGeneration = a.state.Applied[w.ID]
		ws := a.workers[w.ID]
		switch {
		case ws != nil && ws.generation == w.Generation && ws.attempts >= MaxAttempts && !ws.busy:
			obs.State, obs.Message = cloudagent.ObservedError, ws.lastError
		case ws != nil && ws.busy:
			obs.State, obs.Message = busyState(w.Power), ws.message
		case !exists:
			obs.State = cloudagent.ObservedAbsent
		case inst.Running:
			obs.State = cloudagent.ObservedRunning
		default:
			obs.State = cloudagent.ObservedStopped
		}
		if ws != nil && !ws.busy && ws.lastError != "" && obs.State != cloudagent.ObservedError && ws.generation == w.Generation {
			obs.Message = fmt.Sprintf("retrying after error (attempt %d of %d): %s", ws.attempts, MaxAttempts, ws.lastError)
		}
		a.mu.Unlock()

		if obs.State == cloudagent.ObservedRunning {
			if u, ok := a.sampleUsage(ctx, w); ok {
				cpu, mem := u.CPUPercent, u.MemoryUsedMiB
				obs.CPUPercent, obs.MemoryUsedMiB = &cpu, &mem
			}
		}
		out = append(out, obs)
	}
	return out
}

func busyState(power string) string {
	switch power {
	case cloudagent.PowerStopped, cloudagent.PowerAbsent:
		return cloudagent.ObservedStopping
	default:
		return cloudagent.ObservedProvisioning
	}
}

// sampleUsage returns a fresh-enough usage sample, taking a new one when
// the previous is older than UsageInterval.
func (a *Agent) sampleUsage(ctx context.Context, w cloudagent.DesiredWorkload) (runtime.Usage, bool) {
	a.mu.Lock()
	prev, ok := a.usage[w.ID]
	a.mu.Unlock()
	if ok && a.now().Sub(prev.at) < UsageInterval {
		return runtime.Usage{}, false // report only new samples
	}
	rt, ok := a.runtimes[w.Kind]
	if !ok {
		return runtime.Usage{}, false
	}
	u, ok := rt.Usage(ctx, w.ID, w.VCPUs)
	if !ok {
		return runtime.Usage{}, false
	}
	a.mu.Lock()
	a.usage[w.ID] = usageSample{at: a.now(), usage: u}
	a.mu.Unlock()
	return u, true
}

func (a *Agent) listAll(ctx context.Context) map[string]runtime.Instance {
	all := map[string]runtime.Instance{}
	for kind, rt := range a.runtimes {
		instances, err := rt.List(ctx)
		if err != nil {
			a.logger.WarnContext(ctx, "list instances failed", slog.String("runtime", kind), slog.String("error", err.Error()))
			continue
		}
		for id, inst := range instances {
			all[id] = inst
		}
	}
	return all
}

// RunReconciler converges the host whenever desired state arrives, and at
// least every interval. It blocks until ctx is cancelled and then waits for
// running workers to stop.
func (a *Agent) RunReconciler(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			a.mu.Lock()
			for _, ws := range a.workers {
				if ws.cancel != nil {
					ws.cancel()
				}
			}
			a.mu.Unlock()
			a.wg.Wait()
			return
		case <-a.reconcileWake:
		case <-ticker.C:
		}
		a.Reconcile(ctx)
	}
}

// Reconcile performs one pass: networks, workloads, then garbage.
func (a *Agent) Reconcile(ctx context.Context) {
	a.mu.Lock()
	desired := a.desired
	known := !a.desiredAt.IsZero()
	fresh := known && a.now().Sub(a.desiredAt) < DesiredMaxAge
	a.mu.Unlock()
	if !known {
		return // nothing known yet; never act on an empty picture
	}

	networkKinds := map[string]map[string]bool{} // network id -> kinds using it
	for _, w := range desired.Workloads {
		if networkKinds[w.NetworkID] == nil {
			networkKinds[w.NetworkID] = map[string]bool{}
		}
		networkKinds[w.NetworkID][w.Kind] = true
	}
	networksByID := map[string]cloudagent.DesiredNetwork{}
	for _, n := range desired.Networks {
		networksByID[n.ID] = n
	}
	a.syncNetworks(ctx, desired.Networks, networkKinds, fresh)

	instances := a.listAll(ctx)
	desiredIDs := map[string]bool{}
	for _, w := range desired.Workloads {
		desiredIDs[w.ID] = true
		a.reconcileWorkload(ctx, w, networksByID[w.NetworkID], instances)
	}
	a.collectOrphans(ctx, instances, desiredIDs, fresh)
	a.forgetDeleted(desiredIDs)
}

// syncNetworks gives each runtime the networks its workloads need and
// removes, after a grace period, managed networks nobody needs.
func (a *Agent) syncNetworks(ctx context.Context, desired []cloudagent.DesiredNetwork, kinds map[string]map[string]bool, fresh bool) {
	for kind, rt := range a.runtimes {
		var mine []cloudagent.DesiredNetwork
		wanted := map[string]bool{}
		for _, n := range desired {
			if kinds[n.ID][kind] {
				mine = append(mine, n)
				wanted[n.Bridge] = true
			}
		}
		var remove []string
		if existing, err := rt.ListNetworks(ctx); err == nil && fresh {
			a.mu.Lock()
			for _, bridge := range existing {
				key := kind + "/" + bridge
				if wanted[bridge] {
					delete(a.networksSeen, key)
					continue
				}
				first, seen := a.networksSeen[key]
				if !seen {
					a.networksSeen[key] = a.now()
				} else if a.now().Sub(first) >= NetworkGrace {
					remove = append(remove, bridge)
					delete(a.networksSeen, key)
				}
			}
			a.mu.Unlock()
		}
		if err := rt.SyncNetworks(ctx, mine, remove); err != nil {
			a.logger.WarnContext(ctx, "network sync failed", slog.String("runtime", kind), slog.String("error", err.Error()))
		}
	}
}

// matches reports whether the instance already is as desired.
func matches(power string, inst runtime.Instance, exists bool) bool {
	switch power {
	case cloudagent.PowerRunning:
		return exists && inst.Running
	case cloudagent.PowerStopped:
		return !exists || !inst.Running
	default:
		return !exists
	}
}

func (a *Agent) reconcileWorkload(ctx context.Context, w cloudagent.DesiredWorkload, network cloudagent.DesiredNetwork, instances map[string]runtime.Instance) {
	inst, exists := instances[w.ID]

	a.mu.Lock()
	defer a.mu.Unlock()
	ws := a.workers[w.ID]
	if ws != nil && ws.busy {
		return
	}
	if ws != nil && ws.generation != w.Generation {
		// A new generation starts with a clean slate of attempts.
		ws = nil
		delete(a.workers, w.ID)
	}
	if matches(w.Power, inst, exists) {
		if a.state.Applied[w.ID] != w.Generation {
			a.state.Applied[w.ID] = w.Generation
			a.persistLocked()
			signal(a.reportWake)
		}
		if ws != nil {
			delete(a.workers, w.ID)
		}
		return
	}
	if ws != nil && (ws.attempts >= MaxAttempts || a.now().Before(ws.retryAt)) {
		return
	}
	if _, ok := a.runtimes[w.Kind]; !ok {
		if ws == nil {
			ws = &workerState{generation: w.Generation}
			a.workers[w.ID] = ws
		}
		ws.attempts, ws.lastError = MaxAttempts, fmt.Sprintf("this node cannot run %s workloads", w.Kind)
		return
	}

	if ws == nil {
		ws = &workerState{generation: w.Generation}
		a.workers[w.ID] = ws
	}
	workCtx, cancel := context.WithCancel(ctx)
	ws.busy, ws.cancel, ws.message = true, cancel, ""
	a.wg.Add(1)
	go a.work(workCtx, cancel, w, network, inst, exists)
}

func (a *Agent) progress(id string) runtime.Progress {
	return func(msg string) {
		a.mu.Lock()
		if ws := a.workers[id]; ws != nil {
			ws.message = msg
		}
		a.mu.Unlock()
	}
}

// work runs one convergence attempt for a workload.
func (a *Agent) work(ctx context.Context, cancel context.CancelFunc, w cloudagent.DesiredWorkload,
	network cloudagent.DesiredNetwork, inst runtime.Instance, exists bool) {
	defer a.wg.Done()
	defer cancel()
	rt := a.runtimes[w.Kind]
	progress := a.progress(w.ID)

	err := converge(ctx, rt, w, network, inst, exists, progress, a.stopTimeout(w.Kind))

	a.mu.Lock()
	ws := a.workers[w.ID]
	if ws == nil || ws.generation != w.Generation {
		a.mu.Unlock()
		return
	}
	ws.busy, ws.cancel, ws.message = false, nil, ""
	switch {
	case err == nil:
		a.state.Applied[w.ID] = w.Generation
		a.persistLocked()
		delete(a.workers, w.ID)
		a.logger.Info("workload converged", slog.String("workload_id", w.ID), slog.String("power", w.Power),
			slog.Int64("generation", w.Generation))
	case ctx.Err() != nil:
		// Cancelled for a newer generation or shutdown; not a failure.
	default:
		ws.attempts++
		ws.lastError = truncate(err.Error(), maxErrorMessage)
		if ws.attempts < MaxAttempts {
			ws.retryAt = a.now().Add(backoff[ws.attempts-1])
		}
		a.logger.Warn("workload convergence failed", slog.String("workload_id", w.ID),
			slog.Int("attempt", ws.attempts), slog.String("error", err.Error()))
	}
	a.mu.Unlock()
	signal(a.reportWake)
	signal(a.reconcileWake)
}

func (a *Agent) stopTimeout(kind string) time.Duration {
	if kind == cloudagent.KindVM {
		return VMStopTimeout
	}
	return 15 * time.Second
}

// converge performs the steps that take the instance to its desired power.
func converge(ctx context.Context, rt runtime.Runtime, w cloudagent.DesiredWorkload, network cloudagent.DesiredNetwork,
	inst runtime.Instance, exists bool, progress runtime.Progress, stopTimeout time.Duration) error {
	switch w.Power {
	case cloudagent.PowerRunning:
		if !exists {
			progress("creating")
			if err := rt.Create(ctx, w, network, progress); err != nil {
				return err
			}
		}
		if !inst.Running {
			progress("starting")
			return rt.Start(ctx, w.ID)
		}
		return nil

	case cloudagent.PowerStopped:
		progress("stopping")
		return stopAndWait(ctx, rt, w.ID, stopTimeout, progress)

	default: // absent
		progress("deleting")
		if exists && inst.Running {
			if err := rt.Kill(ctx, w.ID); err != nil {
				return err
			}
		}
		return rt.Delete(ctx, w.ID)
	}
}

// stopAndWait requests a clean shutdown and powers off after timeout.
func stopAndWait(ctx context.Context, rt runtime.Runtime, id string, timeout time.Duration, progress runtime.Progress) error {
	if err := rt.Stop(ctx, id); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		instances, err := rt.List(ctx)
		if err != nil {
			return err
		}
		if inst, ok := instances[id]; !ok || !inst.Running {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	progress("did not shut down in time; powering off")
	return rt.Kill(ctx, id)
}

// collectOrphans removes managed instances that are not desired, after
// OrphanGrace, and only while the desired state is fresh: an agent that
// cannot reach the control plane never deletes anything.
func (a *Agent) collectOrphans(ctx context.Context, instances map[string]runtime.Instance, desired map[string]bool, fresh bool) {
	a.mu.Lock()
	var remove []string
	for id := range instances {
		if desired[id] {
			delete(a.orphansSeen, id)
			continue
		}
		first, seen := a.orphansSeen[id]
		switch {
		case !seen:
			a.orphansSeen[id] = a.now()
		case fresh && a.now().Sub(first) >= OrphanGrace:
			remove = append(remove, id)
			delete(a.orphansSeen, id)
		}
	}
	for id := range a.orphansSeen {
		if _, ok := instances[id]; !ok {
			delete(a.orphansSeen, id)
		}
	}
	a.mu.Unlock()

	for _, id := range remove {
		for kind, rt := range a.runtimes {
			list, err := rt.List(ctx)
			if err != nil {
				continue
			}
			inst, ok := list[id]
			if !ok {
				continue
			}
			a.logger.Warn("removing orphaned instance", slog.String("workload_id", id), slog.String("runtime", kind))
			if inst.Running {
				_ = rt.Kill(ctx, id)
			}
			if err := rt.Delete(ctx, id); err != nil {
				a.logger.Warn("orphan removal failed", slog.String("workload_id", id), slog.String("error", err.Error()))
			}
		}
	}
}

// forgetDeleted drops bookkeeping of workloads that are no longer desired.
func (a *Agent) forgetDeleted(desired map[string]bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := false
	for id := range a.state.Applied {
		if !desired[id] {
			delete(a.state.Applied, id)
			changed = true
		}
	}
	for id, ws := range a.workers {
		if !desired[id] && !ws.busy {
			delete(a.workers, id)
		}
	}
	for id := range a.usage {
		if !desired[id] {
			delete(a.usage, id)
		}
	}
	if changed {
		a.persistLocked()
	}
}

func (a *Agent) persistLocked() {
	if err := saveState(statePath(a.dataDir), a.state); err != nil {
		a.logger.Error("persist agent state", slog.String("error", err.Error()))
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
