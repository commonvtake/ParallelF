// Package api serves pf-vpnd's user API under /api/v1/vpn.
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
	"github.com/commonvtake/parallelf/services/vpn/internal/domain"
)

// Store is the persistence the API needs.
type Store interface {
	ListGateways(ctx context.Context) ([]domain.Gateway, error)
	DeleteGateway(ctx context.Context, id string, actor domain.Actor) error

	ListDevices(ctx context.Context, owner string, ended bool) ([]domain.Device, error)
	GetDevice(ctx context.Context, id string) (domain.Device, error)
	CreateDevice(ctx context.Context, in domain.DeviceInput, owner domain.Owner, actor domain.Actor) (domain.Device, string, error)
	DeviceConfig(ctx context.Context, d domain.Device) (domain.ClientConfig, error)
	Activate(ctx context.Context, id string, until time.Time, actor domain.Actor) (domain.Device, error)
	Deactivate(ctx context.Context, id string, actor domain.Actor) (domain.Device, error)
	Revoke(ctx context.Context, id string, actor domain.Actor) (domain.Device, error)
	SetGroups(ctx context.Context, id string, groups []string, actor domain.Actor) (domain.Device, error)
	DeviceMetrics(ctx context.Context, id string, since time.Time) ([]domain.MetricPoint, error)

	ListPolicies(ctx context.Context) ([]domain.Policy, error)
	GetPolicy(ctx context.Context, id string) (domain.Policy, error)
	CreatePolicy(ctx context.Context, in domain.PolicyInput, actor domain.Actor) (domain.Policy, error)
	DeletePolicy(ctx context.Context, id string, actor domain.Actor) error

	ListAudit(ctx context.Context, f auditlog.Filter) ([]auditlog.View, error)
	VerifyAudit(ctx context.Context) (auditlog.Verification, error)
}

// Activation settles how activations work.
type Activation struct {
	Default time.Duration
	Min     time.Duration
	Max     time.Duration
	// MaxAuthAge is how recent the caller's interactive sign-in must be to
	// activate a device; zero disables the check.
	MaxAuthAge time.Duration
	// RequireMFA additionally demands a second factor in the token's amr.
	RequireMFA bool
}

// API serves the routes.
type API struct {
	store      Store
	activation Activation
	logger     *slog.Logger
	now        func() time.Time
	tunnel     netip.Prefix
}

// New returns an API.
func New(s Store, activation Activation, tunnel netip.Prefix, logger *slog.Logger) *API {
	return &API{store: s, activation: activation, logger: logger, now: time.Now, tunnel: tunnel}
}

// Register mounts every route on mux. authenticate must be authn.Require.
func (a *API) Register(mux *http.ServeMux, authenticate httpx.Middleware) {
	handle := func(pattern, permission string, h http.HandlerFunc) {
		mux.Handle(pattern, httpx.Chain(h, authenticate, authz.Require(permission)))
	}
	const base = "/api/v1/vpn"
	handle("GET "+base+"/gateways", authz.VPNResourcesRead, a.listGateways)
	handle("DELETE "+base+"/gateways/{id}", authz.VPNGatewaysManage, a.deleteGateway)

	handle("GET "+base+"/devices", authz.VPNResourcesRead, a.listDevices)
	handle("POST "+base+"/devices", authz.VPNDevicesUse, a.createDevice)
	handle("GET "+base+"/devices/{id}", authz.VPNResourcesRead, a.getDevice)
	handle("GET "+base+"/devices/{id}/config", authz.VPNResourcesRead, a.deviceConfig)
	handle("GET "+base+"/devices/{id}/metrics", authz.VPNResourcesRead, a.deviceMetrics)
	handle("POST "+base+"/devices/{id}/activate", authz.VPNDevicesUse, a.activate)
	handle("POST "+base+"/devices/{id}/deactivate", authz.VPNDevicesUse, a.deactivate)
	handle("PUT "+base+"/devices/{id}/groups", authz.VPNDevicesManage, a.setGroups)
	handle("DELETE "+base+"/devices/{id}", authz.VPNDevicesUse, a.revoke)

	handle("GET "+base+"/policies", authz.VPNResourcesRead, a.listPolicies)
	handle("POST "+base+"/policies", authz.VPNPoliciesManage, a.createPolicy)
	handle("DELETE "+base+"/policies/{id}", authz.VPNPoliciesManage, a.deletePolicy)

	handle("GET "+base+"/audit", authz.VPNAuditRead, a.listAudit)
	handle("GET "+base+"/audit/verify", authz.VPNAuditRead, a.verifyAudit)
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

func canManage(r *http.Request) bool {
	return authz.Allowed(principal(r).Roles, authz.VPNDevicesManage)
}

func pathID(w http.ResponseWriter, r *http.Request, what string) (string, bool) {
	id := r.PathValue("id")
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

func (a *API) fail(w http.ResponseWriter, r *http.Request, err error) {
	var v *domain.ValidationError
	switch {
	case errors.As(err, &v):
		errs := make([]httpx.FieldError, 0, len(v.Errors))
		for _, e := range v.Errors {
			errs = append(errs, httpx.FieldError{Field: e.Field, Code: e.Code, Message: e.Message})
		}
		httpx.WriteProblem(w, r, httpx.Unprocessable("The request is not valid.", errs...))
	case errors.Is(err, domain.ErrNotFound), errors.Is(err, domain.ErrNotOwner):
		// Another user's device is reported as missing, not as forbidden.
		httpx.WriteProblem(w, r, httpx.NotFound("No such resource."))
	case errors.Is(err, domain.ErrNameTaken):
		httpx.WriteProblem(w, r, httpx.Conflict("The name is already used."))
	case errors.Is(err, domain.ErrKeyTaken):
		httpx.WriteProblem(w, r, httpx.Conflict("This public key is already enrolled. Generate a new key pair for each device."))
	case errors.Is(err, domain.ErrInvalidState):
		httpx.WriteProblem(w, r, httpx.Conflict("The device's current state does not allow this operation."))
	case errors.Is(err, domain.ErrNoGateway):
		httpx.WriteProblem(w, r, httpx.NewProblem("no-gateway", http.StatusConflict, "No VPN gateway",
			"No VPN gateway has registered yet. Install pf-wg-agent on the gateway host first."))
	case errors.Is(err, domain.ErrPoolExhausted):
		httpx.WriteProblem(w, r, httpx.Conflict("The tunnel address pool is exhausted."))
	case errors.Is(err, domain.ErrGatewayActive):
		httpx.WriteProblem(w, r, httpx.Conflict("The gateway is still reporting. Stop its agent first."))
	case errors.Is(err, domain.ErrPSKUnavailable):
		httpx.WriteProblem(w, r, httpx.Unprocessable("Pre-shared keys are not configured on this server.",
			httpx.FieldError{Field: "preshared_key", Code: "unavailable", Message: "Set PF_VPN_PSK_KEY to enable pre-shared keys."}))
	case errors.Is(err, domain.ErrReauthenticate):
		httpx.WriteProblem(w, r, httpx.NewProblem("reauthentication-required", http.StatusForbidden, "Recent sign-in required",
			"Activating a device requires a sign-in within the last "+a.activation.MaxAuthAge.String()+". Sign in again, then retry."))
	case errors.Is(err, domain.ErrMFARequired):
		httpx.WriteProblem(w, r, httpx.NewProblem("mfa-required", http.StatusForbidden, "Multi-factor sign-in required",
			"Activating a device requires a sign-in with a second factor."))
	default:
		a.logger.ErrorContext(r.Context(), "request failed", slog.String("error", err.Error()))
		httpx.WriteProblem(w, r, httpx.Internal())
	}
}

// --- Gateways ---------------------------------------------------------------------

func (a *API) listGateways(w http.ResponseWriter, r *http.Request) {
	gws, err := a.store.ListGateways(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(gws))
}

func (a *API) deleteGateway(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "gateway")
	if !ok {
		return
	}
	gws, err := a.store.ListGateways(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	i := slices.IndexFunc(gws, func(g domain.Gateway) bool { return g.ID == id })
	if i < 0 {
		a.fail(w, r, domain.ErrNotFound)
		return
	}
	if !confirmed(w, r, "gateway", gws[i].Name) {
		return
	}
	if err := a.store.DeleteGateway(r.Context(), id, actor(r)); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Devices -----------------------------------------------------------------------

// device loads a device the caller may see: their own, or any for managers.
func (a *API) device(w http.ResponseWriter, r *http.Request) (domain.Device, bool) {
	id, ok := pathID(w, r, "device")
	if !ok {
		return domain.Device{}, false
	}
	d, err := a.store.GetDevice(r.Context(), id)
	if err == nil && d.OwnerSubject != principal(r).Subject && !canManage(r) {
		err = domain.ErrNotOwner
	}
	if err != nil {
		a.fail(w, r, err)
		return domain.Device{}, false
	}
	return d, true
}

func (a *API) listDevices(w http.ResponseWriter, r *http.Request) {
	owner := principal(r).Subject
	if r.URL.Query().Get("scope") == "all" {
		if !canManage(r) {
			httpx.WriteProblem(w, r, httpx.Forbidden("Listing every user's devices requires vpn.devices.manage."))
			return
		}
		owner = ""
	}
	ended := r.URL.Query().Get("include") == "ended"
	devices, err := a.store.ListDevices(r.Context(), owner, ended)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(devices))
}

// Enrolment is the response to creating a device.
type Enrolment struct {
	Device domain.Device       `json:"device"`
	Config domain.ClientConfig `json:"config"`
}

func (a *API) createDevice(w http.ResponseWriter, r *http.Request) {
	var in domain.DeviceInput
	if problem := httpx.DecodeJSON(r, &in); problem != nil {
		httpx.WriteProblem(w, r, *problem)
		return
	}
	if err := in.Validate(); err != nil {
		a.fail(w, r, err)
		return
	}
	p := principal(r)
	// A device starts in its owner's platform-role groups (identity-provider
	// housekeeping roles are left out); managers may regroup it.
	var platformRoles []string
	for _, role := range p.Roles {
		if slices.Contains(authz.Roles(), role) {
			platformRoles = append(platformRoles, role)
		}
	}
	groups, err := domain.ValidGroups(platformRoles)
	if err != nil || groups == nil {
		groups = []string{}
	}
	d, psk, err := a.store.CreateDevice(r.Context(), in, domain.Owner{Subject: p.Subject, Name: p.Username, Groups: groups}, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	cfg, err := a.store.DeviceConfig(r.Context(), d)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	cfg.PresharedKey = psk
	w.Header().Set("Location", "/api/v1/vpn/devices/"+d.ID)
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusCreated, Enrolment{Device: d, Config: cfg})
}

func (a *API) getDevice(w http.ResponseWriter, r *http.Request) {
	if d, ok := a.device(w, r); ok {
		httpx.WriteJSON(w, http.StatusOK, d)
	}
}

func (a *API) deviceConfig(w http.ResponseWriter, r *http.Request) {
	d, ok := a.device(w, r)
	if !ok {
		return
	}
	if !d.Live() {
		a.fail(w, r, domain.ErrInvalidState)
		return
	}
	cfg, err := a.store.DeviceConfig(r.Context(), d)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, cfg)
}

// windows maps the metrics window parameter to a duration.
var windows = map[string]time.Duration{"15m": 15 * time.Minute, "1h": time.Hour, "6h": 6 * time.Hour, "24h": 24 * time.Hour}

// Metrics is the response of the metrics endpoint.
type Metrics struct {
	Window string               `json:"window"`
	Points []domain.MetricPoint `json:"points"`
}

func (a *API) deviceMetrics(w http.ResponseWriter, r *http.Request) {
	d, ok := a.device(w, r)
	if !ok {
		return
	}
	name := r.URL.Query().Get("window")
	if name == "" {
		name = "1h"
	}
	window, ok := windows[name]
	if !ok {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Unknown window.",
			httpx.FieldError{Field: "window", Code: "enum", Message: "15m, 1h, 6h or 24h."}))
		return
	}
	points, err := a.store.DeviceMetrics(r.Context(), d.ID, a.now().Add(-window))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if points == nil {
		points = []domain.MetricPoint{}
	}
	httpx.WriteJSON(w, http.StatusOK, Metrics{Window: name, Points: points})
}

// ActivationRequest optionally sets how long the activation lasts.
type ActivationRequest struct {
	TTLSeconds int `json:"ttl_seconds"`
}

// checkStepUp enforces the recent (and optionally multi-factor) sign-in
// that activation requires.
func (a *API) checkStepUp(p authn.Principal) error {
	if a.activation.RequireMFA && !slices.ContainsFunc(p.AMR, func(m string) bool {
		return m == "otp" || m == "mfa" || m == "hwk" || m == "swk"
	}) {
		return domain.ErrMFARequired
	}
	if a.activation.MaxAuthAge > 0 && (p.AuthTime.IsZero() || a.now().Sub(p.AuthTime) > a.activation.MaxAuthAge) {
		return domain.ErrReauthenticate
	}
	return nil
}

func (a *API) activate(w http.ResponseWriter, r *http.Request) {
	d, ok := a.device(w, r)
	if !ok {
		return
	}
	// Activation is for the device's owner, even for managers: access is
	// personal and must follow the owner's own step-up sign-in.
	if d.OwnerSubject != principal(r).Subject {
		httpx.WriteProblem(w, r, httpx.Forbidden("Only the device's owner can activate it."))
		return
	}
	var in ActivationRequest
	if r.ContentLength != 0 {
		if problem := httpx.DecodeJSON(r, &in); problem != nil {
			httpx.WriteProblem(w, r, *problem)
			return
		}
	}
	ttl := a.activation.Default
	if in.TTLSeconds != 0 {
		ttl = time.Duration(in.TTLSeconds) * time.Second
		if ttl < a.activation.Min || ttl > a.activation.Max {
			httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid activation length.", httpx.FieldError{
				Field: "ttl_seconds", Code: "range",
				Message: "Between " + strconv.Itoa(int(a.activation.Min.Seconds())) + " and " + strconv.Itoa(int(a.activation.Max.Seconds())) + " seconds.",
			}))
			return
		}
	}
	if err := a.checkStepUp(principal(r)); err != nil {
		a.fail(w, r, err)
		return
	}
	d, err := a.store.Activate(r.Context(), d.ID, a.now().Add(ttl).UTC().Truncate(time.Second), actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (a *API) deactivate(w http.ResponseWriter, r *http.Request) {
	d, ok := a.device(w, r)
	if !ok {
		return
	}
	d, err := a.store.Deactivate(r.Context(), d.ID, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

// GroupsRequest replaces a device's groups.
type GroupsRequest struct {
	Groups []string `json:"groups"`
}

func (a *API) setGroups(w http.ResponseWriter, r *http.Request) {
	d, ok := a.device(w, r)
	if !ok {
		return
	}
	var in GroupsRequest
	if problem := httpx.DecodeJSON(r, &in); problem != nil {
		httpx.WriteProblem(w, r, *problem)
		return
	}
	groups, err := domain.ValidGroups(in.Groups)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	d, err = a.store.SetGroups(r.Context(), d.ID, groups, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (a *API) revoke(w http.ResponseWriter, r *http.Request) {
	d, ok := a.device(w, r)
	if !ok {
		return
	}
	if !confirmed(w, r, "device revocation", d.Name) {
		return
	}
	d, err := a.store.Revoke(r.Context(), d.ID, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

// --- Policies -----------------------------------------------------------------------

func (a *API) listPolicies(w http.ResponseWriter, r *http.Request) {
	ps, err := a.store.ListPolicies(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list(ps))
}

func (a *API) createPolicy(w http.ResponseWriter, r *http.Request) {
	var in domain.PolicyInput
	if problem := httpx.DecodeJSON(r, &in); problem != nil {
		httpx.WriteProblem(w, r, *problem)
		return
	}
	if err := in.Validate(a.tunnel); err != nil {
		a.fail(w, r, err)
		return
	}
	p, err := a.store.CreatePolicy(r.Context(), in, actor(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/vpn/policies/"+p.ID)
	httpx.WriteJSON(w, http.StatusCreated, p)
}

func (a *API) deletePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "policy")
	if !ok {
		return
	}
	p, err := a.store.GetPolicy(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !confirmed(w, r, "policy deletion", p.Name) {
		return
	}
	if err := a.store.DeletePolicy(r.Context(), id, actor(r)); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Audit ----------------------------------------------------------------------------

// AuditPage is a page of audit entries.
type AuditPage struct {
	Items      []auditlog.View `json:"items"`
	NextBefore int64           `json:"next_before,omitempty"`
}

func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := auditlog.Filter{ResourceType: q.Get("resource_type"), ResourceID: q.Get("resource_id"), Limit: 50}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid limit.", httpx.FieldError{Field: "limit", Code: "range", Message: "1 to 500."}))
			return
		}
		f.Limit = n
	}
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid cursor.", httpx.FieldError{Field: "before", Code: "format", Message: "A sequence number."}))
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
