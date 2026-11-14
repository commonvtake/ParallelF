// Package api serves pf-cloudd's user-facing HTTP API under /api/v1/cloud
// (contract: api/openapi/parallelf.v1.yaml). Requests arrive through
// pf-gateway; every route verifies the caller's token itself.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/authz"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/ids"
	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
	"github.com/commonvtake/parallelf/services/cloud/internal/ipam"
)

// Store is the persistence the API needs.
type Store interface {
	ListNodes(ctx context.Context) ([]domain.Node, error)
	GetNode(ctx context.Context, id string) (domain.Node, error)
	SetNodeSchedulable(ctx context.Context, id string, schedulable bool, actor domain.Actor) (domain.Node, error)
	DeleteNode(ctx context.Context, id string, actor domain.Actor) error
	NodeMetrics(ctx context.Context, id string, since time.Time) ([]domain.MetricPoint, error)

	ListFlavors(ctx context.Context) ([]domain.Flavor, error)
	ListTemplates(ctx context.Context) ([]domain.Template, error)

	CreateNetwork(ctx context.Context, in domain.NetworkInput, actor domain.Actor) (domain.Network, error)
	ListNetworks(ctx context.Context, projectID string) ([]domain.Network, error)
	GetNetwork(ctx context.Context, id string) (domain.Network, error)
	DeleteNetwork(ctx context.Context, id string, actor domain.Actor) error

	CreateWorkload(ctx context.Context, in domain.WorkloadInput, actor domain.Actor) (domain.Workload, error)
	ListWorkloads(ctx context.Context, f domain.WorkloadFilter) ([]domain.Workload, error)
	GetWorkload(ctx context.Context, id string) (domain.Workload, error)
	ChangeDesiredState(ctx context.Context, id string, op domain.Operation, actor domain.Actor) (domain.Workload, error)
	WorkloadEvents(ctx context.Context, id string, limit int) ([]domain.WorkloadEvent, error)
	WorkloadMetrics(ctx context.Context, id string, since time.Time) ([]domain.MetricPoint, error)

	GetQuota(ctx context.Context, projectID string) (domain.Quota, domain.Usage, error)
	PutQuota(ctx context.Context, q domain.Quota, actor domain.Actor) (domain.Quota, error)

	ListAudit(ctx context.Context, f domain.AuditFilter) ([]domain.AuditEntry, error)
	VerifyAudit(ctx context.Context) (domain.AuditVerification, error)
}

// Projects checks project existence with pf-core.
type Projects interface {
	ProjectExists(ctx context.Context, authorization, projectID string) (bool, error)
}

// API holds the HTTP handlers.
type API struct {
	store    Store
	projects Projects
	logger   *slog.Logger
	now      func() time.Time
	// Scheduled is signalled after a workload is admitted, so the scheduler
	// places it at once instead of at its next sweep. May be nil.
	Scheduled chan<- struct{}
}

// New returns an API.
func New(s Store, p Projects, logger *slog.Logger) *API {
	return &API{store: s, projects: p, logger: logger, now: time.Now}
}

// Register mounts every route on mux. authenticate must be authn.Require.
func (a *API) Register(mux *http.ServeMux, authenticate httpx.Middleware) {
	handle := func(pattern, permission string, h http.HandlerFunc) {
		mux.Handle(pattern, httpx.Chain(h, authenticate, authz.Require(permission)))
	}
	const base = "/api/v1/cloud"

	handle("GET "+base+"/nodes", authz.CloudResourcesRead, a.listNodes)
	handle("GET "+base+"/nodes/{id}", authz.CloudResourcesRead, a.getNode)
	handle("GET "+base+"/nodes/{id}/metrics", authz.CloudResourcesRead, a.nodeMetrics)
	handle("POST "+base+"/nodes/{id}/cordon", authz.CloudNodesManage, a.cordonNode(false))
	handle("POST "+base+"/nodes/{id}/uncordon", authz.CloudNodesManage, a.cordonNode(true))
	handle("DELETE "+base+"/nodes/{id}", authz.CloudNodesManage, a.deleteNode)

	handle("GET "+base+"/flavors", authz.CloudResourcesRead, a.listFlavors)
	handle("GET "+base+"/templates", authz.CloudResourcesRead, a.listTemplates)

	handle("GET "+base+"/networks", authz.CloudResourcesRead, a.listNetworks)
	handle("POST "+base+"/networks", authz.CloudNetworksManage, a.createNetwork)
	handle("GET "+base+"/networks/{id}", authz.CloudResourcesRead, a.getNetwork)
	handle("DELETE "+base+"/networks/{id}", authz.CloudNetworksManage, a.deleteNetwork)

	handle("GET "+base+"/workloads", authz.CloudResourcesRead, a.listWorkloads)
	handle("POST "+base+"/workloads", authz.CloudWorkloadsManage, a.createWorkload)
	handle("GET "+base+"/workloads/{id}", authz.CloudResourcesRead, a.getWorkload)
	handle("DELETE "+base+"/workloads/{id}", authz.CloudWorkloadsManage, a.deleteWorkload)
	handle("POST "+base+"/workloads/{id}/start", authz.CloudWorkloadsManage, a.operate(domain.OpStart))
	handle("POST "+base+"/workloads/{id}/stop", authz.CloudWorkloadsManage, a.operate(domain.OpStop))
	handle("POST "+base+"/workloads/{id}/retry", authz.CloudWorkloadsManage, a.operate(domain.OpRetry))
	handle("GET "+base+"/workloads/{id}/events", authz.CloudResourcesRead, a.workloadEvents)
	handle("GET "+base+"/workloads/{id}/metrics", authz.CloudResourcesRead, a.workloadMetrics)

	handle("GET "+base+"/quotas/{project_id}", authz.CloudResourcesRead, a.getQuota)
	handle("PUT "+base+"/quotas/{project_id}", authz.CloudQuotasManage, a.putQuota)

	handle("GET "+base+"/audit", authz.CloudAuditRead, a.listAudit)
	handle("GET "+base+"/audit/verify", authz.CloudAuditRead, a.verifyAudit)
}

// List is the envelope of every collection response.
type List[T any] struct {
	Items []T `json:"items"`
}

func list[T any](items []T) List[T] {
	if items == nil {
		items = []T{}
	}
	return List[T]{Items: items}
}

func actor(r *http.Request) domain.Actor {
	p, _ := authn.PrincipalFrom(r.Context())
	return domain.Actor{Type: "user", ID: p.Subject, Name: p.Username, RequestID: httpx.RequestIDFrom(r.Context())}
}

// pathID reads a UUID path value. A malformed id cannot name a resource,
// so it is reported as not found.
func pathID(w http.ResponseWriter, r *http.Request, name, what string) (string, bool) {
	id := r.PathValue(name)
	if !ids.IsUUID(id) {
		httpx.WriteProblem(w, r, httpx.NotFound("No "+what+" has this id."))
		return "", false
	}
	return id, true
}

// confirmed implements the destructive-operation guard: the request must
// repeat the resource's name in ?confirm=. A mistyped id or an accidental
// replay of a DELETE therefore cannot remove anything.
func confirmed(w http.ResponseWriter, r *http.Request, what, name string) bool {
	if r.URL.Query().Get("confirm") == name {
		return true
	}
	httpx.WriteProblem(w, r, httpx.NewProblem("confirmation-required", http.StatusPreconditionRequired,
		"Confirmation required",
		"Deleting a "+what+" cannot be undone. Repeat its name in the confirm query parameter: ?confirm="+name))
	return false
}

// checkProject answers 422 unless the project exists in pf-core.
func (a *API) checkProject(w http.ResponseWriter, r *http.Request, projectID string) bool {
	if !ids.IsUUID(projectID) {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid project.",
			httpx.FieldError{Field: "project_id", Code: "format", Message: "project_id must be a project id."}))
		return false
	}
	ok, err := a.projects.ProjectExists(r.Context(), r.Header.Get("Authorization"), projectID)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "project lookup failed", slog.String("error", err.Error()))
		httpx.WriteProblem(w, r, httpx.BadGateway("The core service could not confirm the project."))
		return false
	}
	if !ok {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid project.",
			httpx.FieldError{Field: "project_id", Code: "not_found", Message: "No project has this id."}))
		return false
	}
	return true
}

func (a *API) fail(w http.ResponseWriter, r *http.Request, err error) {
	var (
		validation *domain.ValidationError
		quota      *domain.QuotaError
	)
	switch {
	case errors.As(err, &validation):
		httpx.WriteProblem(w, r, httpx.Unprocessable("The request is not valid.",
			httpx.FieldError{Field: validation.Field, Code: validation.Code, Message: validation.Message}))
	case errors.As(err, &quota):
		p := httpx.NewProblem("quota-exceeded", http.StatusUnprocessableEntity, "Project quota exceeded",
			"The workload would exceed the project's quota.")
		for _, field := range quota.Exceeded {
			p.Errors = append(p.Errors, httpx.FieldError{Field: field, Code: "quota", Message: "Exceeds the project quota for " + field + "."})
		}
		httpx.WriteProblem(w, r, p)
	case errors.Is(err, domain.ErrNotFound):
		httpx.WriteProblem(w, r, httpx.NotFound("No such resource."))
	case errors.Is(err, domain.ErrNameTaken):
		httpx.WriteProblem(w, r, httpx.Conflict("The name is already used in this project."))
	case errors.Is(err, domain.ErrCIDROverlap):
		httpx.WriteProblem(w, r, httpx.Conflict("The CIDR overlaps an existing network."))
	case errors.Is(err, domain.ErrNetworkInUse):
		httpx.WriteProblem(w, r, httpx.Conflict("The network still has workloads. Delete them first."))
	case errors.Is(err, domain.ErrNetworkExhausted):
		httpx.WriteProblem(w, r, httpx.Conflict("The network has no free address."))
	case errors.Is(err, domain.ErrInvalidState):
		httpx.WriteProblem(w, r, httpx.Conflict("The resource's current state does not allow this operation."))
	case errors.Is(err, domain.ErrNodeActive):
		httpx.WriteProblem(w, r, httpx.Conflict("The node is still reporting. Stop its agent first."))
	default:
		a.logger.ErrorContext(r.Context(), "request failed", slog.String("error", err.Error()))
		httpx.WriteProblem(w, r, httpx.Internal())
	}
}

// --- Nodes --------------------------------------------------------------------

func (a *API) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := a.store.ListNodes(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(nodes))
}

func (a *API) getNode(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "node")
	if !ok {
		return
	}
	n, err := a.store.GetNode(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, n)
}

// Metrics is the response of the metrics endpoints.
type Metrics struct {
	Window string               `json:"window"`
	Points []domain.MetricPoint `json:"points"`
}

func metrics(window string, points []domain.MetricPoint) Metrics {
	if points == nil {
		points = []domain.MetricPoint{}
	}
	return Metrics{Window: window, Points: points}
}

func (a *API) window(w http.ResponseWriter, r *http.Request) (string, time.Time, bool) {
	name := r.URL.Query().Get("window")
	if name == "" {
		name = "1h"
	}
	d, ok := domain.MetricWindows[name]
	if !ok {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid query parameter.",
			httpx.FieldError{Field: "window", Code: "enum", Message: "window must be 15m, 1h, 6h or 24h."}))
		return "", time.Time{}, false
	}
	return name, a.now().Add(-d), true
}

func (a *API) nodeMetrics(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "node")
	if !ok {
		return
	}
	name, since, ok := a.window(w, r)
	if !ok {
		return
	}
	if _, err := a.store.GetNode(r.Context(), id); err != nil {
		a.fail(w, r, err)
		return
	}
	points, err := a.store.NodeMetrics(r.Context(), id, since)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, metrics(name, points))
}

func (a *API) cordonNode(schedulable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r, "id", "node")
		if !ok {
			return
		}
		n, err := a.store.SetNodeSchedulable(r.Context(), id, schedulable, actor(r))
		if err != nil {
			a.fail(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, n)
	}
}

func (a *API) deleteNode(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "node")
	if !ok {
		return
	}
	n, err := a.store.GetNode(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !confirmed(w, r, "node", n.Name) {
		return
	}
	if err := a.store.DeleteNode(r.Context(), id, actor(r)); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Catalogue ------------------------------------------------------------------

func (a *API) listFlavors(w http.ResponseWriter, r *http.Request) {
	flavors, err := a.store.ListFlavors(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(flavors))
}

func (a *API) listTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := a.store.ListTemplates(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(templates))
}

// --- Networks -------------------------------------------------------------------

func projectFilter(w http.ResponseWriter, r *http.Request) (string, bool) {
	p := r.URL.Query().Get("project_id")
	if p != "" && !ids.IsUUID(p) {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid query parameter.",
			httpx.FieldError{Field: "project_id", Code: "format", Message: "project_id must be a project id."}))
		return "", false
	}
	return p, true
}

func (a *API) listNetworks(w http.ResponseWriter, r *http.Request) {
	project, ok := projectFilter(w, r)
	if !ok {
		return
	}
	networks, err := a.store.ListNetworks(r.Context(), project)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(networks))
}

func (a *API) createNetwork(w http.ResponseWriter, r *http.Request) {
	var in domain.NetworkInput
	if problem := httpx.DecodeJSON(r, &in); problem != nil {
		httpx.WriteProblem(w, r, *problem)
		return
	}
	var errs []httpx.FieldError
	if !domain.NamePattern.MatchString(in.Name) {
		errs = append(errs, httpx.FieldError{Field: "name", Code: "format",
			Message: "3-40 characters: lower-case letters, digits and hyphens; starts with a letter."})
	}
	if !ipam.ValidKind(in.Kind) {
		errs = append(errs, httpx.FieldError{Field: "kind", Code: "enum", Message: "kind must be nat, isolated or lab."})
	}
	if _, err := ipam.ValidateCIDR(in.CIDR); err != nil {
		errs = append(errs, httpx.FieldError{Field: "cidr", Code: "format", Message: "CIDR " + err.Error() + "."})
	}
	if len(errs) > 0 {
		httpx.WriteProblem(w, r, httpx.Unprocessable("The network is not valid.", errs...))
		return
	}
	if !a.checkProject(w, r, in.ProjectID) {
		return
	}
	n, err := a.store.CreateNetwork(r.Context(), in, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/cloud/networks/"+n.ID)
	httpx.WriteJSON(w, http.StatusCreated, n)
}

func (a *API) getNetwork(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "network")
	if !ok {
		return
	}
	n, err := a.store.GetNetwork(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, n)
}

func (a *API) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "network")
	if !ok {
		return
	}
	n, err := a.store.GetNetwork(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if n.DeletedAt != nil {
		httpx.WriteProblem(w, r, httpx.NotFound("No network has this id."))
		return
	}
	if !confirmed(w, r, "network", n.Name) {
		return
	}
	if err := a.store.DeleteNetwork(r.Context(), id, actor(r)); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Workloads ------------------------------------------------------------------

var workloadStates = map[string]bool{
	domain.StatePending: true, domain.StateScheduled: true, domain.StateProvisioning: true, domain.StateRunning: true,
	domain.StateStopping: true, domain.StateStopped: true, domain.StateUnknown: true, domain.StateDeleting: true,
	domain.StateDeleted: true, domain.StateError: true,
}

func (a *API) listWorkloads(w http.ResponseWriter, r *http.Request) {
	project, ok := projectFilter(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := domain.WorkloadFilter{ProjectID: project, State: q.Get("state"), NodeID: q.Get("node_id")}
	if f.State != "" && !workloadStates[f.State] {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid query parameter.",
			httpx.FieldError{Field: "state", Code: "enum", Message: "Unknown workload state."}))
		return
	}
	if f.NodeID != "" && !ids.IsUUID(f.NodeID) {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid query parameter.",
			httpx.FieldError{Field: "node_id", Code: "format", Message: "node_id must be a node id."}))
		return
	}
	workloads, err := a.store.ListWorkloads(r.Context(), f)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(workloads))
}

func (a *API) createWorkload(w http.ResponseWriter, r *http.Request) {
	var in domain.WorkloadInput
	if problem := httpx.DecodeJSON(r, &in); problem != nil {
		httpx.WriteProblem(w, r, *problem)
		return
	}
	errs := in.Validate()
	if !ids.IsUUID(in.NetworkID) {
		errs = append(errs, httpx.FieldError{Field: "network_id", Code: "format", Message: "network_id must be a network id."})
	}
	if len(errs) > 0 {
		httpx.WriteProblem(w, r, httpx.Unprocessable("The workload is not valid.", errs...))
		return
	}
	if !a.checkProject(w, r, in.ProjectID) {
		return
	}
	wl, err := a.store.CreateWorkload(r.Context(), in, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.logger.InfoContext(r.Context(), "workload admitted",
		slog.String("workload_id", wl.ID), slog.String("name", wl.Name), slog.String("ip", wl.IP))
	if a.Scheduled != nil {
		select {
		case a.Scheduled <- struct{}{}:
		default: // a placement pass is already pending
		}
	}
	w.Header().Set("Location", "/api/v1/cloud/workloads/"+wl.ID)
	httpx.WriteJSON(w, http.StatusCreated, wl)
}

func (a *API) getWorkload(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "workload")
	if !ok {
		return
	}
	wl, err := a.store.GetWorkload(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, wl)
}

func (a *API) operate(op domain.Operation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r, "id", "workload")
		if !ok {
			return
		}
		wl, err := a.store.ChangeDesiredState(r.Context(), id, op, actor(r))
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if op == domain.OpRetry && wl.State == domain.StatePending && a.Scheduled != nil {
			select {
			case a.Scheduled <- struct{}{}:
			default:
			}
		}
		httpx.WriteJSON(w, http.StatusAccepted, wl)
	}
}

func (a *API) deleteWorkload(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "workload")
	if !ok {
		return
	}
	wl, err := a.store.GetWorkload(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if wl.State == domain.StateDeleted {
		httpx.WriteProblem(w, r, httpx.NotFound("No workload has this id."))
		return
	}
	if !confirmed(w, r, "workload", wl.Name) {
		return
	}
	wl, err = a.store.ChangeDesiredState(r.Context(), id, domain.OpDelete, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, wl)
}

func (a *API) workloadEvents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "workload")
	if !ok {
		return
	}
	if _, err := a.store.GetWorkload(r.Context(), id); err != nil {
		a.fail(w, r, err)
		return
	}
	events, err := a.store.WorkloadEvents(r.Context(), id, 200)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(events))
}

func (a *API) workloadMetrics(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "workload")
	if !ok {
		return
	}
	name, since, ok := a.window(w, r)
	if !ok {
		return
	}
	if _, err := a.store.GetWorkload(r.Context(), id); err != nil {
		a.fail(w, r, err)
		return
	}
	points, err := a.store.WorkloadMetrics(r.Context(), id, since)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, metrics(name, points))
}

// --- Quotas -----------------------------------------------------------------------

// QuotaResponse pairs a quota with what the project uses.
type QuotaResponse struct {
	Quota domain.Quota `json:"quota"`
	Usage domain.Usage `json:"usage"`
}

// QuotaInput is the body of PUT /quotas/{project_id}.
type QuotaInput struct {
	MaxVCPUs     int `json:"max_vcpus"`
	MaxMemoryMiB int `json:"max_memory_mib"`
	MaxDiskGiB   int `json:"max_disk_gib"`
	MaxWorkloads int `json:"max_workloads"`
}

func (a *API) getQuota(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project_id")
	if !ids.IsUUID(project) {
		httpx.WriteProblem(w, r, httpx.NotFound("No project has this id."))
		return
	}
	q, u, err := a.store.GetQuota(r.Context(), project)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, QuotaResponse{Quota: q, Usage: u})
}

func (a *API) putQuota(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project_id")
	var in QuotaInput
	if problem := httpx.DecodeJSON(r, &in); problem != nil {
		httpx.WriteProblem(w, r, *problem)
		return
	}
	var errs []httpx.FieldError
	for field, v := range map[string]int{"max_vcpus": in.MaxVCPUs, "max_memory_mib": in.MaxMemoryMiB,
		"max_disk_gib": in.MaxDiskGiB, "max_workloads": in.MaxWorkloads} {
		if v < 0 || v > 1_000_000 {
			errs = append(errs, httpx.FieldError{Field: field, Code: "range", Message: field + " must be between 0 and 1000000."})
		}
	}
	if len(errs) > 0 {
		httpx.WriteProblem(w, r, httpx.Unprocessable("The quota is not valid.", errs...))
		return
	}
	if !a.checkProject(w, r, project) {
		return
	}
	q, err := a.store.PutQuota(r.Context(), domain.Quota{
		ProjectID: project, MaxVCPUs: in.MaxVCPUs, MaxMemoryMiB: in.MaxMemoryMiB,
		MaxDiskGiB: in.MaxDiskGiB, MaxWorkloads: in.MaxWorkloads,
	}, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	_, u, err := a.store.GetQuota(r.Context(), project)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, QuotaResponse{Quota: q, Usage: u})
}

// --- Audit --------------------------------------------------------------------------

// AuditPage is one page of the audit trail, newest first.
type AuditPage struct {
	Items      []domain.AuditEntry `json:"items"`
	NextBefore int64               `json:"next_before,omitempty"`
}

func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := domain.AuditFilter{ResourceType: q.Get("resource_type"), ResourceID: q.Get("resource_id"), Limit: 50}
	if v := q.Get("limit"); v != "" {
		n, err := parsePositive(v)
		if err != nil || n > 200 {
			httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid query parameter.",
				httpx.FieldError{Field: "limit", Code: "range", Message: "limit must be between 1 and 200."}))
			return
		}
		f.Limit = int(n)
	}
	if v := q.Get("before"); v != "" {
		n, err := parsePositive(v)
		if err != nil {
			httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid query parameter.",
				httpx.FieldError{Field: "before", Code: "format", Message: "before must be a sequence number."}))
			return
		}
		f.BeforeSeq = n
	}
	entries, err := a.store.ListAudit(r.Context(), f)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	page := AuditPage{Items: entries}
	if page.Items == nil {
		page.Items = []domain.AuditEntry{}
	}
	if len(entries) == f.Limit {
		page.NextBefore = entries[len(entries)-1].Seq
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

func (a *API) verifyAudit(w http.ResponseWriter, r *http.Request) {
	v, err := a.store.VerifyAudit(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !v.Valid {
		a.logger.ErrorContext(r.Context(), "audit chain verification failed", slog.Int64("first_invalid_seq", v.FirstInvalidSeq))
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func parsePositive(s string) (int64, error) {
	var n int64
	if len(s) == 0 || len(s) > 18 {
		return 0, errors.New("invalid")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid")
		}
		n = n*10 + int64(c-'0')
	}
	if n < 1 {
		return 0, errors.New("invalid")
	}
	return n, nil
}
