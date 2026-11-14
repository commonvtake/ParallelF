package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
)

const (
	projectID  = "01900000-0000-7000-8000-000000000001"
	networkID  = "01900000-0000-7000-8000-000000000002"
	workloadID = "01900000-0000-7000-8000-000000000003"
	nodeID     = "01900000-0000-7000-8000-000000000004"
	unknownID  = "01900000-0000-7000-8000-0000000000ff"
)

type verifier struct{}

func (verifier) Verify(_ context.Context, token string) (*authn.Principal, error) {
	switch token {
	case "owner", "viewer", "operator":
		return &authn.Principal{Subject: "sub-" + token, Username: token, Roles: []string{token}}, nil
	}
	return nil, authn.ErrInvalidToken
}

type projects struct{ err error }

func (p projects) ProjectExists(_ context.Context, auth, id string) (bool, error) {
	if p.err != nil {
		return false, p.err
	}
	return auth != "" && id == projectID, nil
}

// fakeStore records calls and returns canned data.
type fakeStore struct {
	Store // unimplemented methods panic

	workload    domain.Workload
	network     domain.Network
	createErr   error
	changeErr   error
	lastActor   domain.Actor
	lastOp      domain.Operation
	createdWith domain.WorkloadInput
	deleted     bool
}

func (f *fakeStore) GetWorkload(_ context.Context, id string) (domain.Workload, error) {
	if id != f.workload.ID {
		return domain.Workload{}, domain.ErrNotFound
	}
	return f.workload, nil
}

func (f *fakeStore) CreateWorkload(_ context.Context, in domain.WorkloadInput, a domain.Actor) (domain.Workload, error) {
	f.createdWith, f.lastActor = in, a
	if f.createErr != nil {
		return domain.Workload{}, f.createErr
	}
	return domain.Workload{ID: workloadID, Name: in.Name, State: domain.StatePending}, nil
}

func (f *fakeStore) ChangeDesiredState(_ context.Context, id string, op domain.Operation, a domain.Actor) (domain.Workload, error) {
	f.lastOp, f.lastActor = op, a
	if f.changeErr != nil {
		return domain.Workload{}, f.changeErr
	}
	w := f.workload
	w.State = domain.StateDeleting
	return w, nil
}

func (f *fakeStore) GetNetwork(_ context.Context, id string) (domain.Network, error) {
	if id != f.network.ID {
		return domain.Network{}, domain.ErrNotFound
	}
	return f.network, nil
}

func (f *fakeStore) CreateNetwork(_ context.Context, in domain.NetworkInput, a domain.Actor) (domain.Network, error) {
	f.lastActor = a
	return domain.Network{ID: networkID, ProjectID: in.ProjectID, Name: in.Name, Kind: in.Kind, CIDR: in.CIDR}, nil
}

func (f *fakeStore) DeleteNetwork(context.Context, string, domain.Actor) error {
	f.deleted = true
	return nil
}

func (f *fakeStore) ListWorkloads(context.Context, domain.WorkloadFilter) ([]domain.Workload, error) {
	return nil, nil
}

func (f *fakeStore) GetNode(_ context.Context, id string) (domain.Node, error) {
	if id != nodeID {
		return domain.Node{}, domain.ErrNotFound
	}
	return domain.Node{ID: nodeID, Name: "host-1"}, nil
}

func (f *fakeStore) NodeMetrics(context.Context, string, time.Time) ([]domain.MetricPoint, error) {
	return nil, nil
}

func (f *fakeStore) ListAudit(context.Context, domain.AuditFilter) ([]domain.AuditEntry, error) {
	return nil, nil
}

func newServer(t *testing.T, s *fakeStore, p Projects) (http.Handler, chan struct{}) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a := New(s, p, logger)
	wake := make(chan struct{}, 1)
	a.Scheduled = wake
	mux := http.NewServeMux()
	a.Register(mux, authn.Require(verifier{}, logger))
	return httpx.Chain(mux, httpx.RequestID()), wake
}

func do(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func problem(t *testing.T, rec *httptest.ResponseRecorder) httpx.Problem {
	t.Helper()
	var p httpx.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("not a problem document: %s", rec.Body)
	}
	return p
}

func defaultStore() *fakeStore {
	return &fakeStore{
		workload: domain.Workload{ID: workloadID, Name: "web-1", ProjectID: projectID, State: domain.StateRunning},
		network:  domain.Network{ID: networkID, Name: "net-a", ProjectID: projectID},
	}
}

func TestAuthenticationAndPermissions(t *testing.T) {
	h, _ := newServer(t, defaultStore(), projects{})

	if rec := do(h, "GET", "/api/v1/cloud/workloads", "", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/v1/cloud/workloads", "viewer", ""); rec.Code != http.StatusOK {
		t.Errorf("viewer read: %d", rec.Code)
	}
	body := `{"project_id":"` + projectID + `","name":"web-1","template":"cirros","network_id":"` + networkID + `"}`
	if rec := do(h, "POST", "/api/v1/cloud/workloads", "viewer", body); rec.Code != http.StatusForbidden {
		t.Errorf("viewer create: %d", rec.Code)
	}
	if rec := do(h, "POST", "/api/v1/cloud/nodes/"+nodeID+"/cordon", "operator", ""); rec.Code != http.StatusForbidden {
		t.Errorf("operator cordon: %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/v1/cloud/audit", "viewer", ""); rec.Code != http.StatusForbidden {
		t.Errorf("viewer audit: %d", rec.Code)
	}
}

func TestCreateWorkload(t *testing.T) {
	s := defaultStore()
	h, wake := newServer(t, s, projects{})
	body := `{"project_id":"` + projectID + `","name":"web-1","template":"cirros","network_id":"` + networkID +
		`","ssh_authorized_keys":["ssh-ed25519 AAAAC3Nza key"]}`

	rec := do(h, "POST", "/api/v1/cloud/workloads", "operator", body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Location") != "/api/v1/cloud/workloads/"+workloadID {
		t.Errorf("location %q", rec.Header().Get("Location"))
	}
	if s.lastActor.ID != "sub-operator" || s.lastActor.Type != "user" || s.lastActor.RequestID == "" {
		t.Errorf("actor %+v", s.lastActor)
	}
	select {
	case <-wake:
	default:
		t.Error("admission must wake the scheduler")
	}
}

func TestCreateWorkloadValidation(t *testing.T) {
	h, _ := newServer(t, defaultStore(), projects{})
	body := `{"project_id":"` + projectID + `","name":"Bad Name","template":"","network_id":"x",` +
		`"ssh_authorized_keys":["not a key"],"env":{"1BAD":"v"}}`

	rec := do(h, "POST", "/api/v1/cloud/workloads", "operator", body)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status %d", rec.Code)
	}
	fields := map[string]bool{}
	for _, e := range problem(t, rec).Errors {
		fields[e.Field] = true
	}
	for _, f := range []string{"name", "template", "network_id", "ssh_authorized_keys[0]", "env.1BAD"} {
		if !fields[f] {
			t.Errorf("missing field error %s in %v", f, fields)
		}
	}
}

func TestUnknownProjectIsRejected(t *testing.T) {
	h, _ := newServer(t, defaultStore(), projects{})
	body := `{"project_id":"` + unknownID + `","name":"web-1","template":"cirros","network_id":"` + networkID + `"}`

	rec := do(h, "POST", "/api/v1/cloud/workloads", "operator", body)

	if rec.Code != http.StatusUnprocessableEntity || problem(t, rec).Errors[0].Field != "project_id" {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
}

func TestCoreOutageIsABadGateway(t *testing.T) {
	h, _ := newServer(t, defaultStore(), projects{err: errors.New("dial tcp: refused")})
	body := `{"project_id":"` + projectID + `","name":"net-a","kind":"nat","cidr":"10.20.1.0/24"}`

	rec := do(h, "POST", "/api/v1/cloud/networks", "operator", body)

	if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "refused") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
}

func TestQuotaExceededListsTheLimits(t *testing.T) {
	s := defaultStore()
	s.createErr = &domain.QuotaError{Exceeded: []string{"vcpus", "memory_mib"}}
	h, _ := newServer(t, s, projects{})
	body := `{"project_id":"` + projectID + `","name":"web-1","template":"cirros","network_id":"` + networkID + `"}`

	rec := do(h, "POST", "/api/v1/cloud/workloads", "operator", body)

	p := problem(t, rec)
	if rec.Code != http.StatusUnprocessableEntity || p.Type != httpx.ProblemTypeBase+"quota-exceeded" || len(p.Errors) != 2 {
		t.Fatalf("status %d: %+v", rec.Code, p)
	}
}

func TestStoreErrorsMapToProblems(t *testing.T) {
	cases := []struct {
		err    error
		status int
	}{
		{&domain.ValidationError{Field: "network_id", Code: "lab_requires_vm", Message: "no"}, 422},
		{domain.ErrNameTaken, 409},
		{domain.ErrNetworkExhausted, 409},
		{errors.New("connection reset by peer"), 500},
	}
	for _, tc := range cases {
		s := defaultStore()
		s.createErr = tc.err
		h, _ := newServer(t, s, projects{})
		body := `{"project_id":"` + projectID + `","name":"web-1","template":"cirros","network_id":"` + networkID + `"}`
		rec := do(h, "POST", "/api/v1/cloud/workloads", "operator", body)
		if rec.Code != tc.status {
			t.Errorf("%v: status %d, want %d", tc.err, rec.Code, tc.status)
		}
		if strings.Contains(rec.Body.String(), "connection reset") {
			t.Error("internal error text leaked")
		}
	}
}

func TestDeleteRequiresTypedConfirmation(t *testing.T) {
	s := defaultStore()
	h, _ := newServer(t, s, projects{})
	path := "/api/v1/cloud/workloads/" + workloadID

	for _, q := range []string{"", "?confirm=web", "?confirm=WEB-1"} {
		rec := do(h, "DELETE", path+q, "operator", "")
		if rec.Code != http.StatusPreconditionRequired || problem(t, rec).Type != httpx.ProblemTypeBase+"confirmation-required" {
			t.Fatalf("%q: status %d", q, rec.Code)
		}
	}
	if s.lastOp != "" {
		t.Fatal("nothing may change without confirmation")
	}

	rec := do(h, "DELETE", path+"?confirm=web-1", "operator", "")
	if rec.Code != http.StatusAccepted || s.lastOp != domain.OpDelete {
		t.Fatalf("confirmed delete: %d %q", rec.Code, s.lastOp)
	}
}

func TestDeleteNetworkRequiresConfirmation(t *testing.T) {
	s := defaultStore()
	h, _ := newServer(t, s, projects{})

	if rec := do(h, "DELETE", "/api/v1/cloud/networks/"+networkID, "operator", ""); rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("status %d", rec.Code)
	}
	if rec := do(h, "DELETE", "/api/v1/cloud/networks/"+networkID+"?confirm=net-a", "operator", ""); rec.Code != http.StatusNoContent || !s.deleted {
		t.Fatalf("status %d deleted=%v", rec.Code, s.deleted)
	}
}

func TestOperationInWrongStateIsAConflict(t *testing.T) {
	s := defaultStore()
	s.changeErr = domain.ErrInvalidState
	h, _ := newServer(t, s, projects{})

	rec := do(h, "POST", "/api/v1/cloud/workloads/"+workloadID+"/start", "operator", "")

	if rec.Code != http.StatusConflict || s.lastOp != domain.OpStart {
		t.Fatalf("status %d op %q", rec.Code, s.lastOp)
	}
}

func TestMalformedAndUnknownIDs(t *testing.T) {
	h, _ := newServer(t, defaultStore(), projects{})

	for _, path := range []string{"/api/v1/cloud/workloads/not-a-uuid", "/api/v1/cloud/workloads/" + unknownID,
		"/api/v1/cloud/nodes/" + unknownID} {
		if rec := do(h, "GET", path, "viewer", ""); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
}

func TestQueryParameterValidation(t *testing.T) {
	h, _ := newServer(t, defaultStore(), projects{})

	for _, path := range []string{
		"/api/v1/cloud/nodes/" + nodeID + "/metrics?window=2d",
		"/api/v1/cloud/workloads?state=running",
		"/api/v1/cloud/workloads?project_id=nope",
		"/api/v1/cloud/audit?limit=0",
		"/api/v1/cloud/audit?before=-1",
	} {
		token := "viewer"
		if strings.Contains(path, "audit") {
			token = "owner"
		}
		if rec := do(h, "GET", path, token, ""); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	if rec := do(h, "GET", "/api/v1/cloud/nodes/"+nodeID+"/metrics?window=15m", "viewer", ""); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"points":[]`) || !strings.Contains(rec.Body.String(), `"window":"15m"`) {
		t.Errorf("metrics: %d %s", rec.Code, rec.Body)
	}
}

func TestEmptyListsAreArrays(t *testing.T) {
	h, _ := newServer(t, defaultStore(), projects{})

	rec := do(h, "GET", "/api/v1/cloud/workloads", "viewer", "")
	if strings.TrimSpace(rec.Body.String()) != `{"items":[]}` {
		t.Fatalf("body %s", rec.Body)
	}
}
