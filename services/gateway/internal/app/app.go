// Package app assembles pf-gateway's HTTP handler.
package app

import (
	"log/slog"
	"net/http"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/authz"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/version"
	"github.com/commonvtake/parallelf/services/gateway/internal/config"
	"github.com/commonvtake/parallelf/services/gateway/internal/proxy"
	"github.com/commonvtake/parallelf/services/gateway/internal/status"
)

// ServiceName identifies this service in logs and health output.
const ServiceName = "pf-gateway"

// maxBodyBytes bounds request bodies accepted at the edge.
const maxBodyBytes = 1 << 20

// NewHandler returns the gateway's HTTP handler.
//
// Routing:
//
//	GET /healthz, /readyz        unauthenticated probes of the gateway itself
//	GET /api/v1/system/status    aggregated platform health (authenticated)
//	/api/v1/core/...             pf-core   (authenticated)
//	/api/v1/cloud/...            pf-cloudd (authenticated)
//	/api/v1/ai/...               pf-aid    (authenticated)
//
// Every /api/ route requires a valid access token. Upstreams receive the
// same token and verify it again; the gateway is not a trusted hop.
func NewHandler(cfg config.Config, verifier authn.Verifier, transport http.RoundTripper, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	httpx.NewHealth(ServiceName, version.Version, logger).Register(mux)

	authenticate := authn.Require(verifier, logger)

	checker := status.NewChecker(ServiceName, version.Version, []status.Target{
		{Name: "core", Kind: "service", URL: cfg.CoreURL.String() + "/readyz", ExposeChecks: true},
		{Name: "cloud", Kind: "service", URL: cfg.CloudURL.String() + "/readyz", ExposeChecks: true},
		{Name: "ai", Kind: "service", URL: cfg.AIURL.String() + "/readyz", ExposeChecks: true},
		{Name: "identity-provider", Kind: "identity-provider", URL: cfg.OIDC.JWKSURL},
	}, transport)
	mux.Handle("GET /api/v1/system/status",
		httpx.Chain(checker.Handler(), authenticate, authz.Require(authz.SystemStatusRead)))

	mux.Handle("/api/v1/core/", httpx.Chain(proxy.New("core", cfg.CoreURL, transport, logger), authenticate))
	mux.Handle("/api/v1/cloud/", httpx.Chain(proxy.New("cloud", cfg.CloudURL, transport, logger), authenticate))
	mux.Handle("/api/v1/ai/", httpx.Chain(proxy.New("ai", cfg.AIURL, transport, logger), authenticate))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteProblem(w, r, httpx.NotFound("No such route."))
	})

	return httpx.Chain(mux,
		httpx.RequestID(),
		httpx.AccessLog(logger),
		httpx.Recover(logger),
		httpx.SecurityHeaders(),
		httpx.MaxBody(maxBodyBytes),
	)
}
