// Package proxy forwards authenticated API requests to upstream services.
package proxy

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/commonvtake/parallelf/pkg/httpx"
)

// gatewayOwnedHeaders are response headers the gateway's own middleware
// sets; copies from an upstream would only duplicate them.
var gatewayOwnedHeaders = []string{
	httpx.RequestIDHeader,
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Content-Security-Policy",
}

// NewTransport returns the HTTP transport shared by every upstream.
func NewTransport() *http.Transport {
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   32,
		ForceAttemptHTTP2:     false,
	}
}

// New returns a reverse proxy to target. The request path is forwarded
// unchanged, the Authorization header is passed through so the upstream can
// verify the token itself, and client-supplied forwarding headers are
// replaced with values the gateway observed.
func New(name string, target *url.URL, transport http.RoundTripper, logger *slog.Logger) http.Handler {
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			pr.Out.Header.Set(httpx.RequestIDHeader, httpx.RequestIDFrom(pr.In.Context()))
		},
		ModifyResponse: func(resp *http.Response) error {
			// The gateway sets these itself; drop upstream duplicates.
			for _, name := range gatewayOwnedHeaders {
				resp.Header.Del(name)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, http.ErrAbortHandler) || r.Context().Err() != nil {
				return // client went away
			}
			logger.ErrorContext(r.Context(), "upstream request failed",
				slog.String("upstream", name), slog.String("error", err.Error()))
			httpx.WriteProblem(w, r, httpx.BadGateway("The "+name+" service did not respond."))
		},
	}
}
