package controller

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/services/vpn/internal/domain"
)

type fake struct {
	deadline, expiredAt, prunedBefore time.Time
}

func (f *fake) MarkSilentGateways(_ context.Context, d time.Time) ([]domain.Gateway, error) {
	f.deadline = d
	return []domain.Gateway{{ID: "g", Name: "gw"}}, nil
}

func (f *fake) ExpireDevices(_ context.Context, now time.Time) (int, error) {
	f.expiredAt = now
	return 1, nil
}

func (f *fake) PruneStats(_ context.Context, before time.Time) (int64, error) {
	f.prunedBefore = before
	return 3, nil
}

func TestPasses(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	f := &fake{}
	c := New(f, Options{GatewayTimeout: 45 * time.Second, StatsRetention: 7 * 24 * time.Hour}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.now = func() time.Time { return now }
	c.Pass(context.Background())
	c.Prune(context.Background())
	if !f.deadline.Equal(now.Add(-45*time.Second)) || !f.expiredAt.Equal(now) || !f.prunedBefore.Equal(now.Add(-7*24*time.Hour)) {
		t.Fatalf("%+v", f)
	}
}
