// Package agentapi serves the node-agent protocol (pkg/cloudagent) on
// pf-cloudd's internal agent port. It is not routed through pf-gateway:
// agents authenticate with the cluster join token to register, and with
// their own node credential afterwards.
package agentapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strings"

	"github.com/commonvtake/parallelf/pkg/authn"
	"github.com/commonvtake/parallelf/pkg/cloudagent"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/services/cloud/internal/cloudinit"
	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
	"github.com/commonvtake/parallelf/services/cloud/internal/ipam"
)

// Store is the persistence the agent API needs.
type Store interface {
	RegisterNode(ctx context.Context, r domain.NodeRegistration, actor domain.Actor) (domain.Node, error)
	AuthenticateNode(ctx context.Context, tokenHash []byte) (domain.Node, error)
	Sync(ctx context.Context, node domain.Node, req cloudagent.SyncRequest) (domain.HostDesiredState, error)
}

// Sync intervals returned to agents.
const (
	ConvergingInterval = 3  // seconds, while something is changing
	SteadyInterval     = 10 // seconds, otherwise
)

// maxWorkloadsPerSync bounds a sync request (body limit is separate).
const maxWorkloadsPerSync = 1000

var nodeName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// API serves the agent protocol.
type API struct {
	store     Store
	joinToken []byte
	logger    *slog.Logger
}

// New returns an API. joinToken is the shared secret agents present to
// register.
func New(s Store, joinToken string, logger *slog.Logger) *API {
	return &API{store: s, joinToken: []byte(joinToken), logger: logger}
}

// Register mounts the agent routes on mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.Handle("POST /agent/v1/register", a.versioned(http.HandlerFunc(a.register)))
	mux.Handle("POST /agent/v1/sync", a.versioned(http.HandlerFunc(a.sync)))
}

func (a *API) versioned(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get(cloudagent.VersionHeader); v != cloudagent.Version {
			httpx.WriteProblem(w, r, httpx.NewProblem("agent-protocol-version", http.StatusBadRequest,
				"Unsupported agent protocol", fmt.Sprintf("This control plane speaks agent protocol %s.", cloudagent.Version)))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HashToken returns the stored form of a node credential.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("agentapi: crypto/rand failed: " + err.Error())
	}
	return "pfnode_" + base64.RawURLEncoding.EncodeToString(b)
}

func (a *API) register(w http.ResponseWriter, r *http.Request) {
	token, ok := authn.BearerToken(r)
	if !ok || subtle.ConstantTimeCompare([]byte(token), a.joinToken) != 1 {
		a.logger.WarnContext(r.Context(), "agent registration refused", slog.String("remote_addr", r.RemoteAddr))
		w.Header().Set("WWW-Authenticate", `Bearer realm="parallelf-agent"`)
		httpx.WriteProblem(w, r, httpx.Unauthorized("A valid join token is required."))
		return
	}
	var req cloudagent.RegisterRequest
	if problem := httpx.DecodeJSON(r, &req); problem != nil {
		httpx.WriteProblem(w, r, *problem)
		return
	}
	req.Name = strings.ToLower(strings.TrimSpace(req.Name))
	if !nodeName.MatchString(req.Name) {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid node name.",
			httpx.FieldError{Field: "name", Code: "format", Message: "Lower-case letters, digits, dots and hyphens; at most 63 characters."}))
		return
	}
	if errs := validInfo(req.Node); len(errs) > 0 {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid node description.", errs...))
		return
	}

	credential := newToken()
	info := req.Node
	node, err := a.store.RegisterNode(r.Context(), domain.NodeRegistration{
		Name: req.Name, AgentVersion: req.AgentVersion, TokenHash: HashToken(credential),
		KVM: info.KVM, Docker: info.Docker, Hypervisor: info.Hypervisor,
		CPUCount: info.CPUCount, MemoryMiB: info.MemoryMiB, DiskGiB: info.DiskGiB,
		ReservedCPUs: info.ReservedCPUs, ReservedMiB: info.ReservedMemoryMiB, ReservedGiB: info.ReservedDiskGiB,
	}, domain.Actor{Type: "agent", RequestID: httpx.RequestIDFrom(r.Context())})
	if err != nil {
		a.logger.ErrorContext(r.Context(), "node registration failed", slog.String("error", err.Error()))
		httpx.WriteProblem(w, r, httpx.Internal())
		return
	}
	a.logger.InfoContext(r.Context(), "node registered", slog.String("node_id", node.ID), slog.String("name", node.Name))
	httpx.WriteJSON(w, http.StatusOK, cloudagent.RegisterResponse{NodeID: node.ID, Token: credential})
}

func validInfo(n cloudagent.NodeInfo) []httpx.FieldError {
	var errs []httpx.FieldError
	check := func(field string, ok bool) {
		if !ok {
			errs = append(errs, httpx.FieldError{Field: "node." + field, Code: "range", Message: field + " is out of range."})
		}
	}
	check("cpu_count", n.CPUCount >= 0 && n.CPUCount <= 4096)
	check("memory_mib", n.MemoryMiB >= 0 && n.MemoryMiB <= 1<<30)
	check("disk_gib", n.DiskGiB >= 0 && n.DiskGiB <= 1<<30)
	check("reserved_cpus", n.ReservedCPUs >= 0 && n.ReservedCPUs <= 4096)
	check("reserved_memory_mib", n.ReservedMemoryMiB >= 0 && n.ReservedMemoryMiB <= 1<<30)
	check("reserved_disk_gib", n.ReservedDiskGiB >= 0 && n.ReservedDiskGiB <= 1<<30)
	check("hypervisor", len(n.Hypervisor) <= 200)
	return errs
}

func (a *API) sync(w http.ResponseWriter, r *http.Request) {
	token, ok := authn.BearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="parallelf-agent"`)
		httpx.WriteProblem(w, r, httpx.Unauthorized("A node credential is required."))
		return
	}
	node, err := a.store.AuthenticateNode(r.Context(), HashToken(token))
	if errors.Is(err, domain.ErrUnauthorizedNode) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="parallelf-agent", error="invalid_token"`)
		httpx.WriteProblem(w, r, httpx.Unauthorized("Unknown node credential. Register the node again."))
		return
	}
	if err != nil {
		a.logger.ErrorContext(r.Context(), "node authentication failed", slog.String("error", err.Error()))
		httpx.WriteProblem(w, r, httpx.Internal())
		return
	}

	var req cloudagent.SyncRequest
	if problem := httpx.DecodeJSON(r, &req); problem != nil {
		httpx.WriteProblem(w, r, *problem)
		return
	}
	if errs := validInfo(req.Node); len(errs) > 0 || len(req.Workloads) > maxWorkloadsPerSync {
		httpx.WriteProblem(w, r, httpx.Unprocessable("Invalid sync report.", errs...))
		return
	}

	desired, err := a.store.Sync(r.Context(), node, req)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "sync failed", slog.String("node_id", node.ID), slog.String("error", err.Error()))
		httpx.WriteProblem(w, r, httpx.Internal())
		return
	}
	resp, err := Render(node.ID, desired)
	if err != nil {
		a.logger.ErrorContext(r.Context(), "render desired state failed", slog.String("node_id", node.ID), slog.String("error", err.Error()))
		httpx.WriteProblem(w, r, httpx.Internal())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// Render converts a host's desired state into the wire protocol. It is a
// pure function: the same state always yields the same response.
func Render(nodeID string, desired domain.HostDesiredState) (cloudagent.SyncResponse, error) {
	resp := cloudagent.SyncResponse{
		NodeID:              nodeID,
		Networks:            []cloudagent.DesiredNetwork{},
		Workloads:           []cloudagent.DesiredWorkload{},
		SyncIntervalSeconds: SteadyInterval,
	}
	if desired.Converging {
		resp.SyncIntervalSeconds = ConvergingInterval
	}

	networks := map[string]*cloudagent.DesiredNetwork{}
	var order []string
	for _, d := range desired.Workloads {
		w, n := d.Workload, d.Network
		prefix, err := netip.ParsePrefix(n.CIDR)
		if err != nil {
			return cloudagent.SyncResponse{}, fmt.Errorf("network %s CIDR %q: %w", n.ID, n.CIDR, err)
		}
		ip, err := netip.ParseAddr(w.IP)
		if err != nil {
			return cloudagent.SyncResponse{}, fmt.Errorf("workload %s address %q: %w", w.ID, w.IP, err)
		}

		dn, ok := networks[n.ID]
		if !ok {
			dn = &cloudagent.DesiredNetwork{ID: n.ID, Kind: n.Kind, Bridge: n.BridgeName, CIDR: prefix.String(),
				Reservations: []cloudagent.DHCPReservation{}}
			if gw, ok := ipam.Gateway(prefix, n.Kind); ok {
				dn.Gateway = gw.String()
			}
			if first, last, ok := ipam.DHCPSpare(prefix, n.Kind); ok {
				dn.DHCPSpareStart, dn.DHCPSpareEnd = first.String(), last.String()
			}
			networks[n.ID] = dn
			order = append(order, n.ID)
		}
		if w.Kind == domain.KindVM && n.Kind != ipam.KindLab && w.DesiredState != domain.DesiredDeleted {
			dn.Reservations = append(dn.Reservations, cloudagent.DHCPReservation{MAC: w.MAC, IP: w.IP, Name: w.Name})
		}

		out := cloudagent.DesiredWorkload{
			ID: w.ID, Name: w.Name, Kind: w.Kind, Generation: w.Generation, Power: power(w.DesiredState),
			VCPUs: w.VCPUs, MemoryMiB: w.MemoryMiB, DiskGiB: w.DiskGiB,
			Image:     cloudagent.Image{Source: d.Template.Image.Source, SHA256: d.Template.Image.SHA256},
			NetworkID: n.ID, IP: w.IP, PrefixLen: prefix.Bits(), MAC: w.MAC,
		}
		switch w.Kind {
		case domain.KindVM:
			gateway, _ := ipam.Gateway(prefix, n.Kind)
			seed, err := cloudinit.Render(cloudinit.Input{
				WorkloadID: w.ID, Hostname: w.Name, TemplateConfig: d.Template.CloudConfig,
				SSHAuthorizedKeys: w.Spec.SSHAuthorizedKeys, StaticNetwork: d.Template.StaticNetwork,
				MAC: w.MAC, IP: ip, Prefix: prefix, Gateway: gateway,
			})
			if err != nil {
				return cloudagent.SyncResponse{}, fmt.Errorf("workload %s cloud-init: %w", w.ID, err)
			}
			out.CloudInit = &seed
		case domain.KindContainer:
			out.Container = &cloudagent.ContainerSpec{Command: d.Template.Command, Env: w.Spec.Env, CapAdd: d.Template.CapAdd}
		}
		resp.Workloads = append(resp.Workloads, out)
	}
	for _, id := range order {
		resp.Networks = append(resp.Networks, *networks[id])
	}
	return resp, nil
}

func power(desired string) string {
	switch desired {
	case domain.DesiredRunning:
		return cloudagent.PowerRunning
	case domain.DesiredStopped:
		return cloudagent.PowerStopped
	default:
		return cloudagent.PowerAbsent
	}
}
