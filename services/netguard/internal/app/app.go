// Package app assembles pf-netguardd's two HTTP handlers.
package app

import (
	"log/slog"
	"net/http"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/version"
	"github.com/commonvtake/parallelf/services/netguard/internal/api"
	"github.com/commonvtake/parallelf/services/netguard/internal/sensorapi"
)

// ServiceName identifies this service in logs and health output.
const ServiceName = "pf-netguardd"

// Dependencies are the collaborators of both handlers.
type Dependencies struct {
	Logger      *slog.Logger
	Verifier    authn.Verifier
	API         *api.API
	SensorAPI   *sensorapi.API
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

// NewAPIHandler serves /api/v1/network and the health probes. Evidence
// uploads (1 MiB, base64 in JSON) need a larger body limit than other APIs.
func NewAPIHandler(deps Dependencies) http.Handler {
	mux := http.NewServeMux()
	health(deps, mux)
	deps.API.Register(mux, authn.Require(deps.Verifier, deps.Logger))
	mux.HandleFunc("/", notFound)
	return httpx.Chain(mux, httpx.RequestID(), httpx.AccessLog(deps.Logger), httpx.Recover(deps.Logger),
		httpx.SecurityHeaders(), httpx.MaxBody(2<<20))
}

// NewSensorHandler serves the sensor protocol and the health probes.
func NewSensorHandler(deps Dependencies) http.Handler {
	mux := http.NewServeMux()
	health(deps, mux)
	deps.SensorAPI.Register(mux)
	mux.HandleFunc("/", notFound)
	return httpx.Chain(mux, httpx.RequestID(), httpx.AccessLog(deps.Logger), httpx.Recover(deps.Logger),
		httpx.SecurityHeaders(), httpx.MaxBody(8<<20))
}
