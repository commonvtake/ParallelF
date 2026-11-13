// Package app assembles pf-core's HTTP handler from its dependencies.
package app

import (
	"log/slog"
	"net/http"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/version"
	"github.com/commonvtake/parallelf/services/core/internal/api"
)

// ServiceName identifies this service in logs and health output.
const ServiceName = "pf-core"

// maxBodyBytes bounds every request body pf-core accepts.
const maxBodyBytes = 1 << 20

// Dependencies are the collaborators the handler needs.
type Dependencies struct {
	Logger   *slog.Logger
	Verifier authn.Verifier
	Projects api.ProjectService
	// ReadyChecks are run by GET /readyz, keyed by dependency name.
	ReadyChecks map[string]httpx.Check
}

// NewHandler returns the complete HTTP handler for pf-core.
func NewHandler(deps Dependencies) http.Handler {
	mux := http.NewServeMux()

	health := httpx.NewHealth(ServiceName, version.Version, deps.Logger)
	for name, check := range deps.ReadyChecks {
		health.AddCheck(name, check)
	}
	health.Register(mux)

	api.New(deps.Projects, deps.Logger).Register(mux, authn.Require(deps.Verifier, deps.Logger))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteProblem(w, r, httpx.NotFound("No such route."))
	})

	return httpx.Chain(mux,
		httpx.RequestID(),
		httpx.AccessLog(deps.Logger),
		httpx.Recover(deps.Logger),
		httpx.SecurityHeaders(),
		httpx.MaxBody(maxBodyBytes),
	)
}
