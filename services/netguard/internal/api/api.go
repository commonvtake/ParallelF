// Package api serves pf-netguardd's user API under /api/v1/network.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/commonvtake/parallelf/pkg/auditlog"
	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/authz"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/ids"
	"github.com/commonvtake/parallelf/services/netguard/internal/domain"
)

// Store is the persistence the API needs.
type Store interface {
	Overview(ctx context.Context) (domain.Overview, error)
	ListSensors(ctx context.Context) ([]domain.Sensor, error)
	GetSensor(ctx context.Context, id string) (domain.Sensor, error)
	DeleteSensor(ctx context.Context, id string, actor domain.Actor) error

	ListEvents(ctx context.Context, f domain.EventFilter) ([]domain.Event, error)
	GetEvent(ctx context.Context, id int64) (domain.Event, error)
	Assets(ctx context.Context) ([]domain.Asset, error)

	ListAlerts(ctx context.Context, f domain.AlertFilter) ([]domain.Alert, error)
	GetAlert(ctx context.Context, id string) (domain.Alert, error)
	AlertEvents(ctx context.Context, a domain.Alert, limit int) ([]domain.Event, error)
	ChangeAlert(ctx context.Context, id string, c domain.AlertChange, actor domain.Actor) (domain.Alert, error)

	ListIncidents(ctx context.Context, status string) ([]domain.Incident, error)
	CreateIncident(ctx context.Context, in domain.IncidentInput, actor domain.Actor) (domain.Incident, error)
	GetIncident(ctx context.Context, id string) (domain.IncidentDetail, error)
	UpdateIncident(ctx context.Context, id string, u domain.IncidentUpdate, actor domain.Actor) (domain.Incident, error)
	AddEvidence(ctx context.Context, incidentID string, in domain.EvidenceInput, actor domain.Actor) (domain.Evidence, error)
	EvidenceContent(ctx context.Context, incidentID, evidenceID string) (domain.Evidence, []byte, error)
	VerifyEvidence(ctx context.Context, incidentID string) (domain.EvidenceVerification, error)

	ListScopes(ctx context.Context) ([]domain.Scope, error)
	GetScope(ctx context.Context, id string) (domain.Scope, error)
	IssueScope(ctx context.Context, in domain.ScopeInput, actor domain.Actor) (domain.Scope, error)
	RevokeScope(ctx context.Context, id string, actor domain.Actor) (domain.Scope, error)

	ListAudit(ctx context.Context, f auditlog.Filter) ([]auditlog.View, error)
	VerifyAudit(ctx context.Context) (auditlog.Verification, error)
}

// StepUp settles the recent sign-in that issuing a discovery scope needs:
// a scope makes a sensor send packets, so it follows the same rule as
// activating a VPN device.
type StepUp struct {
	MaxAuthAge    time.Duration
	ExemptClients []string
}

var errReauthenticate = errors.New("a recent sign-in is required")

// API serves the routes.
type API struct {
	store  Store
	stepUp StepUp
	logger *slog.Logger
	now    func() time.Time
}

// New returns an API.
func New(s Store, stepUp StepUp, logger *slog.Logger) *API {
	return &API{store: s, stepUp: stepUp, logger: logger, now: time.Now}
}

// Register mounts every route on mux. authenticate must be authn.Require.
func (a *API) Register(mux *http.ServeMux, authenticate httpx.Middleware) {
	handle := func(pattern, permission string, h http.HandlerFunc) {
		mux.Handle(pattern, httpx.Chain(h, authenticate, authz.Require(permission)))
	}
	const base = "/api/v1/network"
	handle("GET "+base+"/overview", authz.NetworkResourcesRead, a.overview)
	handle("GET "+base+"/sensors", authz.NetworkResourcesRead, a.listSensors)
	handle("DELETE "+base+"/sensors/{id}", authz.NetworkSensorsManage, a.deleteSensor)
	handle("GET "+base+"/events", authz.NetworkResourcesRead, a.listEvents)
	handle("GET "+base+"/events/{id}", authz.NetworkResourcesRead, a.getEvent)
	handle("GET "+base+"/assets", authz.NetworkResourcesRead, a.listAssets)

	handle("GET "+base+"/alerts", authz.NetworkResourcesRead, a.listAlerts)
	handle("GET "+base+"/alerts/{id}", authz.NetworkResourcesRead, a.getAlert)
	handle("POST "+base+"/alerts/{id}/status", authz.NetworkAlertsTriage, a.changeAlert)

	handle("GET "+base+"/incidents", authz.NetworkResourcesRead, a.listIncidents)
	handle("POST "+base+"/incidents", authz.NetworkAlertsTriage, a.createIncident)
	handle("GET "+base+"/incidents/{id}", authz.NetworkResourcesRead, a.getIncident)
	handle("PATCH "+base+"/incidents/{id}", authz.NetworkAlertsTriage, a.updateIncident)
	handle("POST "+base+"/incidents/{id}/evidence", authz.NetworkAlertsTriage, a.addEvidence)
	handle("GET "+base+"/incidents/{id}/evidence/verify", authz.NetworkResourcesRead, a.verifyEvidence)
	handle("GET "+base+"/incidents/{id}/evidence/{eid}", authz.NetworkResourcesRead, a.evidenceContent)

	handle("GET "+base+"/scopes", authz.NetworkResourcesRead, a.listScopes)
	handle("POST "+base+"/scopes", authz.NetworkScopesManage, a.issueScope)
	handle("DELETE "+base+"/scopes/{id}", authz.NetworkScopesManage, a.revokeScope)

	handle("GET "+base+"/audit", authz.NetworkAuditRead, a.listAudit)
	handle("GET "+base+"/audit/verify", authz.NetworkAuditRead, a.verifyAudit)
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

func principal(r *http.Request) authn.Principal {
	p, _ := authn.PrincipalFrom(r.Context())
	if p == nil {
		return authn.Principal{}
	}
	return *p
}

func actor(r *http.Request) domain.Actor {
	p := principal(r)
	return domain.Actor{Type: "user", ID: p.Subject, Name: p.Username, RequestID: httpx.RequestIDFrom(r.Context())}
}

func pathID(w http.ResponseWriter, r *http.Request, name, what string) (string, bool) {
	id := r.PathValue(name)
	if !ids.IsUUID(id) {
		httpx.WriteProblem(w, r, httpx.NotFound("No "+what+" has this id."))
		return "", false
	}
	return id, true
}

func confirmed(w http.ResponseWriter, r *http.Request, what, name string) bool {
	if r.URL.Query().Get("confirm") == name {
		return true
	}
	httpx.WriteProblem(w, r, httpx.NewProblem("confirmation-required", http.StatusPreconditionRequired,
		"Confirmation required",
		"This "+what+" operation cannot be undone. Repeat its name in the confirm query parameter: ?confirm="+name))
	return false
}

func invalid(w http.ResponseWriter, r *http.Request, field, code, msg string) {
	httpx.WriteProblem(w, r, httpx.Unprocessable("The request is not valid.", httpx.FieldError{Field: field, Code: code, Message: msg}))
}

func (a *API) fail(w http.ResponseWriter, r *http.Request, err error) {
	var v *domain.ValidationError
	switch {
	case errors.As(err, &v):
		errs := make([]httpx.FieldError, 0, len(v.Errors))
		for _, e := range v.Errors {
			errs = append(errs, httpx.FieldError{Field: e.Field, Code: e.Code, Message: e.Message})
		}
		httpx.WriteProblem(w, r, httpx.Unprocessable("The request is not valid.", errs...))
	case errors.Is(err, domain.ErrNotFound):
		httpx.WriteProblem(w, r, httpx.NotFound("No such resource."))
	case errors.Is(err, domain.ErrInvalidState):
		httpx.WriteProblem(w, r, httpx.Conflict("The resource's current state does not allow this operation."))
	case errors.Is(err, domain.ErrSensorActive):
		httpx.WriteProblem(w, r, httpx.Conflict("The sensor is still reporting. Stop pf-ng-sensor first."))
	case errors.Is(err, errReauthenticate):
		httpx.WriteProblem(w, r, httpx.NewProblem("reauthentication-required", http.StatusForbidden, "Recent sign-in required",
			"Issuing a discovery scope requires a sign-in within the last "+a.stepUp.MaxAuthAge.String()+". Sign in again, then retry."))
	default:
		a.logger.ErrorContext(r.Context(), "request failed", slog.String("error", err.Error()))
		httpx.WriteProblem(w, r, httpx.Internal())
	}
}

func (a *API) checkStepUp(p authn.Principal) error {
	if p.ClientID != "" && slices.Contains(a.stepUp.ExemptClients, p.ClientID) {
		return nil
	}
	if a.stepUp.MaxAuthAge > 0 && (p.AuthTime.IsZero() || a.now().Sub(p.AuthTime) > a.stepUp.MaxAuthAge) {
		return errReauthenticate
	}
	return nil
}

func limitParam(w http.ResponseWriter, r *http.Request, def int) (int, bool) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 500 {
		invalid(w, r, "limit", "range", "1 to 500.")
		return 0, false
	}
	return n, true
}

func ipParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	v := r.URL.Query().Get("ip")
	if v == "" {
		return "", true
	}
	ip, err := netip.ParseAddr(v)
	if err != nil {
		invalid(w, r, "ip", "format", "An IP address.")
		return "", false
	}
	return ip.String(), true
}

// --- Overview, sensors, events, assets -------------------------------------------

func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	o, err := a.store.Overview(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, o)
}

func (a *API) listSensors(w http.ResponseWriter, r *http.Request) {
	s, err := a.store.ListSensors(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(s))
}

func (a *API) deleteSensor(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "sensor")
	if !ok {
		return
	}
	s, err := a.store.GetSensor(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !confirmed(w, r, "sensor removal", s.Name) {
		return
	}
	if err := a.store.DeleteSensor(r.Context(), id, actor(r)); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// EventPage is a page of events, newest first.
type EventPage struct {
	Items      []domain.Event `json:"items"`
	NextBefore int64          `json:"next_before,omitempty"`
}

func (a *API) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := domain.EventFilter{Kind: q.Get("kind")}
	var ok bool
	if f.Limit, ok = limitParam(w, r, 100); !ok {
		return
	}
	if f.IP, ok = ipParam(w, r); !ok {
		return
	}
	if f.Kind != "" && !slices.Contains([]string{"flow", "dns", "http", "tls", "alert", "anomaly", "discovery"}, f.Kind) {
		invalid(w, r, "kind", "enum", "flow, dns, http, tls, alert, anomaly or discovery.")
		return
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			invalid(w, r, "since", "format", "An RFC 3339 time.")
			return
		}
		f.Since = t
	}
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			invalid(w, r, "before", "format", "An event id.")
			return
		}
		f.Before = n
	}
	events, err := a.store.ListEvents(r.Context(), f)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	page := EventPage{Items: events}
	if len(events) == f.Limit {
		page.NextBefore = events[len(events)-1].ID
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

func (a *API) getEvent(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		httpx.WriteProblem(w, r, httpx.NotFound("No event has this id."))
		return
	}
	e, err := a.store.GetEvent(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, e)
}

func (a *API) listAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := a.store.Assets(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(assets))
}

// --- Alerts ---------------------------------------------------------------------------

func (a *API) listAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := domain.AlertFilter{Status: q.Get("status"), Detector: q.Get("detector"), Severity: q.Get("severity")}
	var ok bool
	if f.Limit, ok = limitParam(w, r, 100); !ok {
		return
	}
	if f.IP, ok = ipParam(w, r); !ok {
		return
	}
	if f.Status != "" && !slices.Contains([]string{domain.AlertOpen, domain.AlertAcknowledged, domain.AlertClosed, domain.AlertSuppressed}, f.Status) {
		invalid(w, r, "status", "enum", "open, acknowledged, closed or suppressed.")
		return
	}
	if f.Severity != "" && domain.SeverityRank(f.Severity) < 0 {
		invalid(w, r, "severity", "enum", "info, low, medium, high or critical.")
		return
	}
	alerts, err := a.store.ListAlerts(r.Context(), f)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(alerts))
}

// AlertDetail is an alert with the telemetry behind it.
type AlertDetail struct {
	domain.Alert
	Events []domain.Event `json:"events"`
}

func (a *API) getAlert(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "alert")
	if !ok {
		return
	}
	al, err := a.store.GetAlert(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	events, err := a.store.AlertEvents(r.Context(), al, 100)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, AlertDetail{Alert: al, Events: events})
}

// AlertStatusRequest changes an alert's status.
type AlertStatusRequest struct {
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	SuppressFor string `json:"suppress_for"`
}

func (a *API) changeAlert(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "alert")
	if !ok {
		return
	}
	var in AlertStatusRequest
	if p := httpx.DecodeJSON(r, &in); p != nil {
		httpx.WriteProblem(w, r, *p)
		return
	}
	c := domain.AlertChange{Status: in.Status, Reason: in.Reason}
	if in.SuppressFor != "" {
		d, err := time.ParseDuration(in.SuppressFor)
		if err != nil {
			invalid(w, r, "suppress_for", "format", "A duration such as 8h.")
			return
		}
		c.SuppressFor = d
	}
	if err := domain.ValidateAlertChange(c); err != nil {
		a.fail(w, r, err)
		return
	}
	al, err := a.store.ChangeAlert(r.Context(), id, c, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, al)
}

// --- Incidents and evidence ---------------------------------------------------------

func (a *API) listIncidents(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status != "" && !slices.Contains([]string{domain.IncidentOpen, domain.IncidentInvestigating, domain.IncidentResolved}, status) {
		invalid(w, r, "status", "enum", "open, investigating or resolved.")
		return
	}
	inc, err := a.store.ListIncidents(r.Context(), status)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(inc))
}

func (a *API) createIncident(w http.ResponseWriter, r *http.Request) {
	var in domain.IncidentInput
	if p := httpx.DecodeJSON(r, &in); p != nil {
		httpx.WriteProblem(w, r, *p)
		return
	}
	if err := domain.ValidateIncident(in); err != nil {
		a.fail(w, r, err)
		return
	}
	inc, err := a.store.CreateIncident(r.Context(), in, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, inc)
}

func (a *API) getIncident(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "incident")
	if !ok {
		return
	}
	d, err := a.store.GetIncident(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (a *API) updateIncident(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "incident")
	if !ok {
		return
	}
	var u domain.IncidentUpdate
	if p := httpx.DecodeJSON(r, &u); p != nil {
		httpx.WriteProblem(w, r, *p)
		return
	}
	if err := domain.ValidateIncidentUpdate(u); err != nil {
		a.fail(w, r, err)
		return
	}
	inc, err := a.store.UpdateIncident(r.Context(), id, u, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, inc)
}

func (a *API) addEvidence(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "incident")
	if !ok {
		return
	}
	var in domain.EvidenceInput
	if p := httpx.DecodeJSON(r, &in); p != nil {
		httpx.WriteProblem(w, r, *p)
		return
	}
	if err := domain.ValidateEvidence(in); err != nil {
		a.fail(w, r, err)
		return
	}
	ev, err := a.store.AddEvidence(r.Context(), id, in, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, ev)
}

func (a *API) evidenceContent(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "incident")
	if !ok {
		return
	}
	eid, ok := pathID(w, r, "eid", "evidence")
	if !ok {
		return
	}
	ev, content, err := a.store.EvidenceContent(r.Context(), id, eid)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// Served as an attachment with its recorded digest; never rendered.
	w.Header().Set("Content-Type", ev.MediaType)
	w.Header().Set("Content-Disposition", `attachment; filename="evidence-`+ev.ID+`"`)
	w.Header().Set("X-Content-SHA256", ev.SHA256)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (a *API) verifyEvidence(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "incident")
	if !ok {
		return
	}
	v, err := a.store.VerifyEvidence(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

// --- Scopes ---------------------------------------------------------------------------

func (a *API) listScopes(w http.ResponseWriter, r *http.Request) {
	s, err := a.store.ListScopes(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(s))
}

func (a *API) issueScope(w http.ResponseWriter, r *http.Request) {
	var in domain.ScopeInput
	if p := httpx.DecodeJSON(r, &in); p != nil {
		httpx.WriteProblem(w, r, *p)
		return
	}
	if err := a.checkStepUp(principal(r)); err != nil {
		a.fail(w, r, err)
		return
	}
	s, err := a.store.IssueScope(r.Context(), in, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, s)
}

func (a *API) revokeScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id", "scope")
	if !ok {
		return
	}
	s, err := a.store.GetScope(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !confirmed(w, r, "scope revocation", s.Name) {
		return
	}
	s, err = a.store.RevokeScope(r.Context(), id, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s)
}

// --- Audit ------------------------------------------------------------------------------

// AuditPage is a page of audit entries.
type AuditPage struct {
	Items      []auditlog.View `json:"items"`
	NextBefore int64           `json:"next_before,omitempty"`
}

func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := auditlog.Filter{ResourceType: q.Get("resource_type"), ResourceID: q.Get("resource_id")}
	var ok bool
	if f.Limit, ok = limitParam(w, r, 50); !ok {
		return
	}
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			invalid(w, r, "before", "format", "A sequence number.")
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
		page.Items = []auditlog.View{}
	}
	if len(entries) == f.Limit && entries[len(entries)-1].Seq > 1 {
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
	httpx.WriteJSON(w, http.StatusOK, v)
}
