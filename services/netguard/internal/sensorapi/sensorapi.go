// Package sensorapi serves the sensor protocol (pkg/ngsensor) on
// pf-netguardd's internal sensor port. Sensors register with the join
// token and authenticate with their own credential afterwards.
//
// Telemetry is untrusted input: every event is re-validated here, and an
// invalid event is dropped (and counted) instead of failing the batch, so
// one bad line cannot stall a sensor.
package sensorapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/pkg/ngsensor"
	"github.com/commonvtake/parallelf/services/netguard/internal/domain"
)

// Store is the persistence the sensor API needs.
type Store interface {
	RegisterSensor(ctx context.Context, r domain.SensorRegistration) (domain.Sensor, error)
	AuthenticateSensor(ctx context.Context, tokenHash []byte) (domain.Sensor, error)
	Ingest(ctx context.Context, sensor domain.Sensor, req ngsensor.IngestRequest) (int, error)
	ActiveScopes(ctx context.Context) ([]ngsensor.SignedScope, error)
}

var (
	sensorName   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)
	ifacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)
	detailKey    = regexp.MustCompile(`^[a-z0-9_.]{1,64}$`)
	hexDigest    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	kinds        = map[string]bool{
		ngsensor.KindFlow: true, ngsensor.KindDNS: true, ngsensor.KindHTTP: true, ngsensor.KindTLS: true,
		ngsensor.KindAlert: true, ngsensor.KindAnomaly: true, ngsensor.KindDiscovery: true,
	}
)

const maxDetails = 32

// API serves the sensor protocol.
type API struct {
	store     Store
	joinToken []byte
	scopeKey  ed25519.PublicKey
	logger    *slog.Logger
	now       func() time.Time
}

// New returns an API.
func New(s Store, joinToken string, scopeKey ed25519.PublicKey, logger *slog.Logger) *API {
	return &API{store: s, joinToken: []byte(joinToken), scopeKey: scopeKey, logger: logger, now: time.Now}
}

// Register mounts the sensor routes on mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+ngsensor.PathRegister, a.register)
	mux.HandleFunc("POST "+ngsensor.PathIngest, a.ingest)
}

// HashToken is how sensor credentials are stored: only their SHA-256.
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

func checkVersion(w http.ResponseWriter, r *http.Request) bool {
	if v := r.Header.Get(ngsensor.VersionHeader); v != ngsensor.Version {
		httpx.WriteProblem(w, r, httpx.BadRequest("Unsupported sensor protocol version "+v+"; this server speaks "+ngsensor.Version+"."))
		return false
	}
	return true
}

func clean(s string, n int) string {
	if len(s) > n {
		s = s[:n]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

func (a *API) register(w http.ResponseWriter, r *http.Request) {
	if !checkVersion(w, r) {
		return
	}
	if len(a.joinToken) == 0 || subtle.ConstantTimeCompare([]byte(bearer(r)), a.joinToken) != 1 {
		a.logger.WarnContext(r.Context(), "sensor registration with a wrong join token", slog.String("remote", r.RemoteAddr))
		httpx.WriteProblem(w, r, httpx.Unauthorized("Invalid join token."))
		return
	}
	var in ngsensor.RegisterRequest
	if p := httpx.DecodeJSON(r, &in); p != nil {
		httpx.WriteProblem(w, r, *p)
		return
	}
	if !sensorName.MatchString(in.Name) {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid registration.",
			httpx.FieldError{Field: "name", Code: "format", Message: "Lower-case letters, digits, dots and hyphens."}))
		return
	}
	in.Engine, in.AgentVersion = clean(in.Engine, 128), clean(in.AgentVersion, 64)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		httpx.WriteProblem(w, r, httpx.Internal())
		return
	}
	credential := "pfng_" + base64.RawURLEncoding.EncodeToString(raw)
	s, err := a.store.RegisterSensor(r.Context(), domain.SensorRegistration{RegisterRequest: in, TokenHash: HashToken(credential)})
	if err != nil {
		a.logger.ErrorContext(r.Context(), "register sensor", slog.String("error", err.Error()))
		httpx.WriteProblem(w, r, httpx.Internal())
		return
	}
	a.logger.InfoContext(r.Context(), "sensor registered", slog.String("sensor", s.Name), slog.String("sensor_id", s.ID), slog.String("engine", s.Engine))
	httpx.WriteJSON(w, http.StatusOK, ngsensor.RegisterResponse{
		SensorID: s.ID, Credential: credential, ScopePublicKey: base64.StdEncoding.EncodeToString(a.scopeKey),
	})
}

func (a *API) authenticate(w http.ResponseWriter, r *http.Request) (domain.Sensor, bool) {
	token := bearer(r)
	if token == "" {
		httpx.WriteProblem(w, r, httpx.Unauthorized("Missing sensor credential."))
		return domain.Sensor{}, false
	}
	s, err := a.store.AuthenticateSensor(r.Context(), HashToken(token))
	if errors.Is(err, domain.ErrUnauthorizedSens) {
		httpx.WriteProblem(w, r, httpx.Unauthorized("Unknown sensor credential."))
		return domain.Sensor{}, false
	}
	if err != nil {
		a.logger.ErrorContext(r.Context(), "authenticate sensor", slog.String("error", err.Error()))
		httpx.WriteProblem(w, r, httpx.Internal())
		return domain.Sensor{}, false
	}
	return s, true
}

func addr(s string) (string, bool) {
	if s == "" {
		return "", true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	return a.Unmap().String(), true
}

// Sanitize validates one event; ok is false if it must be dropped.
func Sanitize(e ngsensor.Event, now time.Time) (ngsensor.Event, bool) {
	if !kinds[e.Kind] || !hexDigest.MatchString(e.RawSHA256) {
		return e, false
	}
	if e.Time.IsZero() || e.Time.After(now.Add(time.Hour)) || e.Time.Before(now.Add(-30*24*time.Hour)) {
		return e, false
	}
	var ok bool
	if e.SrcIP, ok = addr(e.SrcIP); !ok {
		return e, false
	}
	if e.DstIP, ok = addr(e.DstIP); !ok {
		return e, false
	}
	if e.SrcPort < 0 || e.SrcPort > 65535 || e.DstPort < 0 || e.DstPort > 65535 {
		return e, false
	}
	if e.Interface != "" && !ifacePattern.MatchString(e.Interface) {
		e.Interface = ""
	}
	e.Proto = clean(strings.ToLower(e.Proto), 16)
	e.CommunityID = clean(e.CommunityID, 64)
	e.AppProto = clean(e.AppProto, 32)
	if len(e.Details) > maxDetails {
		return e, false
	}
	details := make(map[string]string, len(e.Details))
	for k, v := range e.Details {
		if !detailKey.MatchString(k) {
			continue
		}
		details[k] = clean(strings.ToValidUTF8(v, "�"), ngsensor.MaxFieldBytes)
	}
	e.Details = details
	return e, true
}

func (a *API) ingest(w http.ResponseWriter, r *http.Request) {
	if !checkVersion(w, r) {
		return
	}
	s, ok := a.authenticate(w, r)
	if !ok {
		return
	}
	var in ngsensor.IngestRequest
	if p := httpx.DecodeJSON(r, &in); p != nil {
		httpx.WriteProblem(w, r, *p)
		return
	}
	if len(in.Events) > ngsensor.MaxBatchEvents {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Batch too large.",
			httpx.FieldError{Field: "events", Code: "too_many", Message: "At most 2000 events per batch."}))
		return
	}
	now := a.now()
	kept := in.Events[:0]
	dropped := 0
	for _, e := range in.Events {
		if e, ok := Sanitize(e, now); ok {
			kept = append(kept, e)
		} else {
			dropped++
		}
	}
	in.Events = kept
	in.Engine, in.EngineError = clean(in.Engine, 128), clean(in.EngineError, 512)
	ifaces := in.Interfaces[:0]
	for _, i := range in.Interfaces {
		if ifacePattern.MatchString(i) && len(ifaces) < 64 {
			ifaces = append(ifaces, i)
		}
	}
	in.Interfaces = ifaces
	if dropped > 0 {
		a.logger.WarnContext(r.Context(), "invalid events dropped", slog.String("sensor", s.Name), slog.Int("dropped", dropped))
	}
	accepted, err := a.store.Ingest(r.Context(), s, in)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "ingest", slog.String("error", err.Error()))
		httpx.WriteProblem(w, r, httpx.Internal())
		return
	}
	scopes, err := a.store.ActiveScopes(r.Context())
	if err != nil {
		a.logger.ErrorContext(r.Context(), "active scopes", slog.String("error", err.Error()))
		scopes = nil
	}
	if scopes == nil {
		scopes = []ngsensor.SignedScope{}
	}
	httpx.WriteJSON(w, http.StatusOK, ngsensor.IngestResponse{Accepted: accepted, Scopes: scopes})
}

// Fingerprint identifies the scope-signing key in logs.
func Fingerprint(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}
