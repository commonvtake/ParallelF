// Package agentapi serves the gateway-agent protocol (pkg/vpnagent) on
// pf-vpnd's internal agent port. Agents register with the join token and
// authenticate with their own gateway credential afterwards.
package agentapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/vpnagent"
	"github.com/commonvtake/parallelf/services/vpn/internal/domain"
)

// Store is the persistence the agent API needs.
type Store interface {
	RegisterGateway(ctx context.Context, r domain.GatewayRegistration) (domain.Gateway, error)
	AuthenticateGateway(ctx context.Context, tokenHash []byte) (domain.Gateway, error)
	Sync(ctx context.Context, gw domain.Gateway, req vpnagent.SyncRequest) error
	DesiredState(ctx context.Context, gw domain.Gateway) (vpnagent.SyncResponse, error)
	Revision(ctx context.Context) (int64, error)
	Changed() <-chan struct{}
}

var gatewayName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// maxPeersPerSync bounds a sync request.
const maxPeersPerSync = 5000

// API serves the agent protocol.
type API struct {
	store     Store
	joinToken []byte
	logger    *slog.Logger
	maxWait   time.Duration
}

// New returns an API.
func New(s Store, joinToken string, logger *slog.Logger) *API {
	return &API{store: s, joinToken: []byte(joinToken), logger: logger, maxWait: vpnagent.MaxWait}
}

// Register mounts the agent routes on mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+vpnagent.PathRegister, a.register)
	mux.HandleFunc("POST "+vpnagent.PathSync, a.sync)
}

// HashToken is how gateway credentials are stored: only their SHA-256.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func bearer(r *http.Request) string {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(token)
}

func (a *API) checkVersion(w http.ResponseWriter, r *http.Request) bool {
	if v := r.Header.Get(vpnagent.VersionHeader); v != vpnagent.Version {
		httpx.WriteProblem(w, r, httpx.BadRequest("Unsupported agent protocol version "+v+"; this server speaks "+vpnagent.Version+"."))
		return false
	}
	return true
}

func (a *API) register(w http.ResponseWriter, r *http.Request) {
	if !a.checkVersion(w, r) {
		return
	}
	if subtle.ConstantTimeCompare([]byte(bearer(r)), a.joinToken) != 1 {
		a.logger.WarnContext(r.Context(), "gateway registration with a wrong join token", slog.String("remote", r.RemoteAddr))
		httpx.WriteProblem(w, r, httpx.Unauthorized("Invalid join token."))
		return
	}
	var in vpnagent.RegisterRequest
	if problem := httpx.DecodeJSON(r, &in); problem != nil {
		httpx.WriteProblem(w, r, *problem)
		return
	}
	var errs []httpx.FieldError
	if !gatewayName.MatchString(in.Name) {
		errs = append(errs, httpx.FieldError{Field: "name", Code: "format", Message: "Lower-case letters, digits, dots and hyphens."})
	}
	if !domain.ValidKey(in.PublicKey) {
		errs = append(errs, httpx.FieldError{Field: "public_key", Code: "format", Message: "A base64 WireGuard public key."})
	}
	if _, port, err := net.SplitHostPort(in.Endpoint); err != nil || port == "" || len(in.Endpoint) > 255 {
		errs = append(errs, httpx.FieldError{Field: "endpoint", Code: "format", Message: "host:port."})
	}
	if in.ListenPort < 1 || in.ListenPort > 65535 {
		errs = append(errs, httpx.FieldError{Field: "listen_port", Code: "range", Message: "1 to 65535."})
	}
	if len(errs) > 0 {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid registration.", errs...))
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		httpx.WriteProblem(w, r, httpx.Internal())
		return
	}
	credential := "pfgw_" + base64.RawURLEncoding.EncodeToString(raw)
	gw, err := a.store.RegisterGateway(r.Context(), domain.GatewayRegistration{RegisterRequest: in, TokenHash: HashToken(credential)})
	if err != nil {
		a.logger.ErrorContext(r.Context(), "register gateway", slog.String("error", err.Error()))
		httpx.WriteProblem(w, r, httpx.Internal())
		return
	}
	a.logger.InfoContext(r.Context(), "gateway registered", slog.String("gateway_id", gw.ID), slog.String("name", gw.Name))
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, vpnagent.RegisterResponse{GatewayID: gw.ID, Credential: credential})
}

func (a *API) sync(w http.ResponseWriter, r *http.Request) {
	if !a.checkVersion(w, r) {
		return
	}
	token := bearer(r)
	if token == "" {
		httpx.WriteProblem(w, r, httpx.Unauthorized("Gateway credential required."))
		return
	}
	gw, err := a.store.AuthenticateGateway(r.Context(), HashToken(token))
	if errors.Is(err, domain.ErrUnauthorizedGW) {
		httpx.WriteProblem(w, r, httpx.Unauthorized("Unknown gateway credential. Register again."))
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in vpnagent.SyncRequest
	if problem := httpx.DecodeJSON(r, &in); problem != nil {
		httpx.WriteProblem(w, r, *problem)
		return
	}
	if len(in.Peers) > maxPeersPerSync {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Too many peers in one sync."))
		return
	}
	if err := a.store.Sync(r.Context(), gw, in); err != nil {
		a.fail(w, r, err)
		return
	}

	// Long-poll: hold the request while the agent is up to date, until the
	// desired state changes or the wait ends. The change channel is taken
	// before reading the revision, so no change can slip in between.
	if wait := min(time.Duration(in.WaitSeconds)*time.Second, a.maxWait); wait > 0 {
		changed := a.store.Changed()
		rev, err := a.store.Revision(r.Context())
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if rev == in.Revision {
			timer := time.NewTimer(wait)
			select {
			case <-changed:
			case <-timer.C:
			case <-r.Context().Done():
				timer.Stop()
				return
			}
			timer.Stop()
		}
	}
	desired, err := a.store.DesiredState(r.Context(), gw)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, desired)
}

func (a *API) fail(w http.ResponseWriter, r *http.Request, err error) {
	a.logger.ErrorContext(r.Context(), "agent request failed", slog.String("error", err.Error()))
	httpx.WriteProblem(w, r, httpx.Internal())
}
