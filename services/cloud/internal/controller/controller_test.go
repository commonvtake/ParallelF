package controller

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
	"github.com/commonvtake/parallelf/services/cloud/internal/scheduler"
)

type fakeStore struct {
	mu          sync.Mutex
	pending     []string
	scheduled   []string
	failOn      string
	deadline    time.Time
	pruneBefore time.Time
}

func (f *fakeStore) PendingWorkloads(context.Context, int) ([]string, error) { return f.pending, nil }

func (f *fakeStore) Schedule(_ context.Context, id string) (scheduler.Result, error) {
	if id == f.failOn {
		return scheduler.Result{}, errors.New("boom")
	}
	f.mu.Lock()
	f.scheduled = append(f.scheduled, id)
	f.mu.Unlock()
	return scheduler.Result{NodeID: "n-1"}, nil
}

func (f *fakeStore) MarkUnresponsiveNodes(_ context.Context, deadline time.Time) ([]domain.Node, error) {
	f.deadline = deadline
	return []domain.Node{{ID: "n-1", Name: "host"}}, nil
}

func (f *fakeStore) DeleteMetricsBefore(_ context.Context, t time.Time) (int64, error) {
	f.pruneBefore = t
	return 3, nil
}

func (f *fakeStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.scheduled)
}

func newController(s *fakeStore) *Controller {
	c := New(s, Options{NodeTimeout: 30 * time.Second, MetricsRetention: 24 * time.Hour}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.now = func() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) }
	return c
}

func TestSchedulePassContinuesAfterAFailure(t *testing.T) {
	s := &fakeStore{pending: []string{"a", "b", "c"}, failOn: "b"}
	newController(s).SchedulePass(context.Background())

	if len(s.scheduled) != 2 || s.scheduled[0] != "a" || s.scheduled[1] != "c" {
		t.Fatalf("scheduled %v", s.scheduled)
	}
}

func TestMonitorUsesTheNodeTimeout(t *testing.T) {
	s := &fakeStore{}
	newController(s).MonitorPass(context.Background())

	if want := time.Date(2026, 11, 13, 11, 59, 30, 0, time.UTC); !s.deadline.Equal(want) {
		t.Fatalf("deadline %v, want %v", s.deadline, want)
	}
}

func TestPruneUsesTheRetention(t *testing.T) {
	s := &fakeStore{}
	newController(s).PrunePass(context.Background())

	if want := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC); !s.pruneBefore.Equal(want) {
		t.Fatalf("prune before %v, want %v", s.pruneBefore, want)
	}
}

func TestWakeTriggersAPass(t *testing.T) {
	s := &fakeStore{pending: []string{"a"}}
	c := newController(s)
	c.opts.SchedulePeriod, c.opts.MonitorPeriod = time.Hour, time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()

	// The first pass runs at start; wake must cause a second one.
	deadline := time.Now().Add(2 * time.Second)
	for s.count() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	c.Wake() <- struct{}{}
	for s.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if s.count() < 2 {
		t.Fatalf("wake did not trigger a pass: %v", s.scheduled)
	}
}
