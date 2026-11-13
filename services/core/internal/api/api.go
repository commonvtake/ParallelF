// Package api exposes pf-core's HTTP API (see api/openapi/parallelf.v1.yaml).
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/authz"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/ids"
	"github.com/commonvtake/parallelf/services/core/internal/projects"
)

// ProjectService is the part of projects.Service the API uses.
type ProjectService interface {
	Create(ctx context.Context, createdBy string, in projects.CreateInput) (projects.Project, error)
	Get(ctx context.Context, id string) (projects.Project, error)
	List(ctx context.Context, cursor string, limit int) (projects.Page, error)
	Delete(ctx context.Context, id, deletedBy string) error
}

// API holds the HTTP handlers.
type API struct {
	projects ProjectService
	logger   *slog.Logger
}

// New returns an API.
func New(projectService ProjectService, logger *slog.Logger) *API {
	return &API{projects: projectService, logger: logger}
}

// Register mounts every route on mux. authenticate must be authn.Require.
func (a *API) Register(mux *http.ServeMux, authenticate httpx.Middleware) {
	handle := func(pattern, permission string, h http.HandlerFunc) {
		mws := []httpx.Middleware{authenticate}
		if permission != "" {
			mws = append(mws, authz.Require(permission))
		}
		mux.Handle(pattern, httpx.Chain(h, mws...))
	}

	handle("GET /api/v1/core/me", "", a.me)
	handle("GET /api/v1/core/projects", authz.CoreProjectsRead, a.listProjects)
	handle("POST /api/v1/core/projects", authz.CoreProjectsCreate, a.createProject)
	handle("GET /api/v1/core/projects/{id}", authz.CoreProjectsRead, a.getProject)
	handle("DELETE /api/v1/core/projects/{id}", authz.CoreProjectsDelete, a.deleteProject)
}

// MeResponse describes the authenticated caller.
type MeResponse struct {
	Subject     string   `json:"subject"`
	Username    string   `json:"username"`
	Email       string   `json:"email,omitempty"`
	Name        string   `json:"name,omitempty"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	p, _ := authn.PrincipalFrom(r.Context())
	// Only platform roles are returned; provider-internal roles are noise.
	roles := make([]string, 0, len(p.Roles))
	known := make(map[string]struct{})
	for _, role := range authz.Roles() {
		known[role] = struct{}{}
	}
	for _, role := range p.Roles {
		if _, ok := known[role]; ok {
			roles = append(roles, role)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, MeResponse{
		Subject:     p.Subject,
		Username:    p.Username,
		Email:       p.Email,
		Name:        p.Name,
		Roles:       roles,
		Permissions: authz.PermissionsFor(roles),
	})
}

func (a *API) listProjects(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	limit := projects.DefaultPageSize
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > projects.MaxPageSize {
			httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid query parameter.",
				httpx.FieldError{Field: "limit", Code: "range", Message: "limit must be between 1 and 200."}))
			return
		}
		limit = n
	}
	cursor := q.Get("cursor")
	if cursor != "" && !ids.IsUUID(cursor) {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid query parameter.",
			httpx.FieldError{Field: "cursor", Code: "format", Message: "cursor is not a value returned by this API."}))
		return
	}

	page, err := a.projects.List(r.Context(), cursor, limit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

func (a *API) createProject(w http.ResponseWriter, r *http.Request) {
	var in projects.CreateInput
	if problem := httpx.DecodeJSON(r, &in); problem != nil {
		httpx.WriteProblem(w, r, *problem)
		return
	}
	if errs := in.Validate(); len(errs) > 0 {
		httpx.WriteProblem(w, r, httpx.Unprocessable("The project is not valid.", errs...))
		return
	}

	principal, _ := authn.PrincipalFrom(r.Context())
	p, err := a.projects.Create(r.Context(), principal.Subject, in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.logger.InfoContext(r.Context(), "project created",
		slog.String("project_id", p.ID), slog.String("slug", p.Slug))
	w.Header().Set("Location", "/api/v1/core/projects/"+p.ID)
	httpx.WriteJSON(w, http.StatusCreated, p)
}

func (a *API) getProject(w http.ResponseWriter, r *http.Request) {
	id, ok := a.projectID(w, r)
	if !ok {
		return
	}
	p, err := a.projects.Get(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (a *API) deleteProject(w http.ResponseWriter, r *http.Request) {
	id, ok := a.projectID(w, r)
	if !ok {
		return
	}
	principal, _ := authn.PrincipalFrom(r.Context())
	if err := a.projects.Delete(r.Context(), id, principal.Subject); err != nil {
		a.fail(w, r, err)
		return
	}
	a.logger.InfoContext(r.Context(), "project deleted", slog.String("project_id", id))
	w.WriteHeader(http.StatusNoContent)
}

// projectID reads the {id} path value. A malformed id cannot name an
// existing project, so it is reported as not found.
func (a *API) projectID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !ids.IsUUID(id) {
		httpx.WriteProblem(w, r, httpx.NotFound("No project has this id."))
		return "", false
	}
	return id, true
}

func (a *API) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, projects.ErrNotFound):
		httpx.WriteProblem(w, r, httpx.NotFound("No project has this id."))
	case errors.Is(err, projects.ErrSlugTaken):
		httpx.WriteProblem(w, r, httpx.Conflict("A project with this slug already exists."))
	default:
		a.logger.ErrorContext(r.Context(), "request failed", slog.String("error", err.Error()))
		httpx.WriteProblem(w, r, httpx.Internal())
	}
}
