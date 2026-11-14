// Package app assembles pf-cloudd's two HTTP handlers.
package app

import (
	"log/slog"
	"net/http"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/version"
	"github.com/commonvtake/parallelf/services/cloud/internal/agentapi"
	"github.com/commonvtake/parallelf/services/cloud/internal/api"
)

// ServiceName identifies this service in logs and health output.
const ServiceName = "pf-cloudd"

const (
	maxBodyBytes      = 1 << 20
	maxAgentBodyBytes = 4 << 20
)

// Dependencies are the collaborators of both handlers.
type Dependencies struct {
	Logger      *slog.Logger
	Verifier    authn.Verifier
	API         *api.API
	AgentAPI    *agentapi.API
	ReadyChecks map[string]httpx.Check
}

func health(deps Dependencies, mux *http.ServeMux) {
	h := httpx.NewHealth(ServiceName, version.Version, deps.Logger)
	for name, check := range deps.ReadyChecks {
		h.AddCheck(name, check)
	}
	h.Register(mux)
}

func notFound(w http.ResponseWriter, r *http.Request) {
	httpx.WriteProblem(w, r, httpx.NotFound("No such route."))
}

// NewAPIHandler serves /api/v1/cloud and the health probes.
func NewAPIHandler(deps Dependencies) http.Handler {
	mux := http.NewServeMux()
	health(deps, mux)
	deps.API.Register(mux, authn.Require(deps.Verifier, deps.Logger))
	mux.HandleFunc("/", notFound)
	return httpx.Chain(mux,
		httpx.RequestID(),
		httpx.AccessLog(deps.Logger),
		httpx.Recover(deps.Logger),
		httpx.SecurityHeaders(),
		httpx.MaxBody(maxBodyBytes),
	)
}

// NewAgentHandler serves the node-agent protocol and the health probes.
func NewAgentHandler(deps Dependencies) http.Handler {
	mux := http.NewServeMux()
	health(deps, mux)
	deps.AgentAPI.Register(mux)
	mux.HandleFunc("/", notFound)
	return httpx.Chain(mux,
		httpx.RequestID(),
		httpx.AccessLog(deps.Logger),
		httpx.Recover(deps.Logger),
		httpx.SecurityHeaders(),
		httpx.MaxBody(maxAgentBodyBytes),
	)
}
