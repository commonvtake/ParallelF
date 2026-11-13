// Package status aggregates the health of the platform's components for
// the dashboard's overview page.
package status

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/commonvtake/parallelf/pkg/httpx"
)

// Component states.
const (
	OK          = "ok"
	Unavailable = "unavailable"
	Degraded    = "degraded"
)

// Target is a component probed over HTTP. It is healthy when URL answers 200.
type Target struct {
	Name string // e.g. "core"
	Kind string // "service" or "identity-provider"
	URL  string
	// ExposeChecks surfaces the target's own readiness checks (for example
	// core's "postgres") as separate components.
	ExposeChecks bool
}

// Component is the health of one part of the platform.
type Component struct {
	Name       string  `json:"name"`
	Kind       string  `json:"kind"`
	Status     string  `json:"status"`
	LatencyMS  float64 `json:"latency_ms,omitempty"`
	Version    string  `json:"version,omitempty"`
	ReportedBy string  `json:"reported_by,omitempty"`
}

// Report is the response of GET /api/v1/system/status.
type Report struct {
	Status     string      `json:"status"` // ok or degraded
	CheckedAt  time.Time   `json:"checked_at"`
	Components []Component `json:"components"`
}

// Checker probes targets concurrently.
type Checker struct {
	self    Component
	targets []Target
	client  *http.Client
	timeout time.Duration
	now     func() time.Time
}

// NewChecker returns a Checker. self describes the gateway itself.
func NewChecker(selfName, selfVersion string, targets []Target, transport http.RoundTripper) *Checker {
	return &Checker{
		self:    Component{Name: selfName, Kind: "service", Status: OK, Version: selfVersion},
		targets: targets,
		client: &http.Client{
			Transport: transport,
			// A probe must describe the target itself, not wherever it redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		timeout: 2 * time.Second,
		now:     time.Now,
	}
}

// Check probes every target and returns the combined report.
func (c *Checker) Check(ctx context.Context) Report {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	results := make([][]Component, len(c.targets))
	var wg sync.WaitGroup
	for i, target := range c.targets {
		wg.Add(1)
		go func(i int, target Target) {
			defer wg.Done()
			results[i] = c.probe(ctx, target)
		}(i, target)
	}
	wg.Wait()

	report := Report{Status: OK, CheckedAt: c.now().UTC(), Components: []Component{c.self}}
	for _, components := range results {
		for _, component := range components {
			if component.Status != OK {
				report.Status = Degraded
			}
			report.Components = append(report.Components, component)
		}
	}
	return report
}

func (c *Checker) probe(ctx context.Context, target Target) []Component {
	component := Component{Name: target.Name, Kind: target.Kind, Status: Unavailable}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return []Component{component}
	}
	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return []Component{component}
	}
	defer func() { _ = resp.Body.Close() }()
	component.LatencyMS = float64(time.Since(start).Microseconds()) / 1000

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusOK {
		component.Status = OK
	}
	out := []Component{component}

	if target.ExposeChecks {
		var health httpx.HealthResponse
		if json.Unmarshal(body, &health) == nil {
			out[0].Version = health.Version
			for _, name := range sortedKeys(health.Checks) {
				state := Unavailable
				if health.Checks[name] == OK {
					state = OK
				}
				out = append(out, Component{Name: name, Kind: "dependency", Status: state, ReportedBy: target.Name})
			}
		}
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Handler serves the report as JSON. The response is always 200: the
// endpoint reports on the platform, it is not itself a health probe.
func (c *Checker) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, c.Check(r.Context()))
	}
}
