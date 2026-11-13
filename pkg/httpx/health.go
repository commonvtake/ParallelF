package httpx

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"
)

// Check reports whether a dependency is usable. It must honour ctx.
type Check func(ctx context.Context) error

// Health serves liveness and readiness endpoints.
//
//	GET /healthz  the process is running (never checks dependencies)
//	GET /readyz   every registered check passes
type Health struct {
	service string
	version string
	timeout time.Duration
	logger  *slog.Logger

	mu     sync.RWMutex
	checks map[string]Check
}

// HealthResponse is the body of both health endpoints.
type HealthResponse struct {
	Status  string            `json:"status"` // "ok" or "unavailable"
	Service string            `json:"service"`
	Version string            `json:"version"`
	Checks  map[string]string `json:"checks,omitempty"`
}

// NewHealth returns a Health for the named service.
func NewHealth(service, version string, logger *slog.Logger) *Health {
	return &Health{
		service: service,
		version: version,
		timeout: 2 * time.Second,
		logger:  logger,
		checks:  make(map[string]Check),
	}
}

// AddCheck registers a readiness check under name.
func (h *Health) AddCheck(name string, check Check) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[name] = check
}

// Register adds the health routes to mux.
func (h *Health) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", h.live)
	mux.HandleFunc("GET /readyz", h.ready)
}

func (h *Health) live(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, HealthResponse{Status: "ok", Service: h.service, Version: h.version})
}

func (h *Health) ready(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	names := make([]string, 0, len(h.checks))
	for name := range h.checks {
		names = append(names, name)
	}
	checks := make(map[string]Check, len(h.checks))
	for name, c := range h.checks {
		checks[name] = c
	}
	h.mu.RUnlock()
	sort.Strings(names)

	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	results := make(map[string]string, len(names))
	var (
		wg sync.WaitGroup
		mu sync.Mutex
		ok = true
	)
	for _, name := range names {
		wg.Add(1)
		go func(name string, check Check) {
			defer wg.Done()
			err := check(ctx)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				ok = false
				// The cause is logged, not returned: readiness output is unauthenticated.
				results[name] = "unavailable"
				h.logger.WarnContext(ctx, "readiness check failed",
					slog.String("check", name), slog.String("error", err.Error()))
				return
			}
			results[name] = "ok"
		}(name, checks[name])
	}
	wg.Wait()

	resp := HealthResponse{Status: "ok", Service: h.service, Version: h.version, Checks: results}
	status := http.StatusOK
	if !ok {
		resp.Status = "unavailable"
		status = http.StatusServiceUnavailable
	}
	WriteJSON(w, status, resp)
}
