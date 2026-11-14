package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
	"github.com/commonvtake/parallelf/pkg/httpx"
	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
)

type fakeStore struct {
	registered domain.NodeRegistration
	tokenHash  []byte
	synced     *cloudagent.SyncRequest
	desired    domain.HostDesiredState
}

func (f *fakeStore) RegisterNode(_ context.Context, r domain.NodeRegistration, _ domain.Actor) (domain.Node, error) {
	f.registered, f.tokenHash = r, r.TokenHash
	return domain.Node{ID: "node-1", Name: r.Name}, nil
}

func (f *fakeStore) AuthenticateNode(_ context.Context, hash []byte) (domain.Node, error) {
	if f.tokenHash == nil || !bytes.Equal(hash, f.tokenHash) {
		return domain.Node{}, domain.ErrUnauthorizedNode
	}
	return domain.Node{ID: "node-1"}, nil
}

func (f *fakeStore) Sync(_ context.Context, _ domain.Node, req cloudagent.SyncRequest) (domain.HostDesiredState, error) {
	f.synced = &req
	return f.desired, nil
}

func server(s *fakeStore) http.Handler {
	mux := http.NewServeMux()
	New(s, "join-secret", slog.New(slog.NewTextHandler(io.Discard, nil))).Register(mux)
	return httpx.Chain(mux, httpx.RequestID())
}

func post(h http.Handler, path, token string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(cloudagent.VersionHeader, cloudagent.Version)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRegisterAndSync(t *testing.T) {
	s := &fakeStore{}
	h := server(s)
	reg := cloudagent.RegisterRequest{Name: "Host-1", AgentVersion: "1.0", Node: cloudagent.NodeInfo{KVM: true, CPUCount: 4, MemoryMiB: 16000}}

	if rec := post(h, "/agent/v1/register", "wrong", reg); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong join token: %d", rec.Code)
	}
	rec := post(h, "/agent/v1/register", "join-secret", reg)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	var resp cloudagent.RegisterResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.NodeID != "node-1" || !strings.HasPrefix(resp.Token, "pfnode_") || len(resp.Token) < 40 {
		t.Fatalf("response %+v", resp)
	}
	if s.registered.Name != "host-1" || !bytes.Equal(s.tokenHash, HashToken(resp.Token)) {
		t.Fatal("only the hash of the credential may be stored, under the normalised name")
	}

	if rec := post(h, "/agent/v1/sync", "join-secret", cloudagent.SyncRequest{}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("join token must not authenticate a sync: %d", rec.Code)
	}
	rec = post(h, "/agent/v1/sync", resp.Token, cloudagent.SyncRequest{AgentVersion: "1.0",
		Workloads: []cloudagent.ObservedWorkload{{ID: "w-1", State: cloudagent.ObservedRunning}}})
	if rec.Code != http.StatusOK || s.synced == nil || len(s.synced.Workloads) != 1 {
		t.Fatalf("sync: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"sync_interval_seconds":10`) {
		t.Fatalf("steady interval expected: %s", rec.Body)
	}
}

func TestProtocolVersionIsChecked(t *testing.T) {
	req := httptest.NewRequest("POST", "/agent/v1/register", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer join-secret")
	rec := httptest.NewRecorder()
	server(&fakeStore{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestRegisterValidatesNameAndCapacity(t *testing.T) {
	h := server(&fakeStore{})
	for _, reg := range []cloudagent.RegisterRequest{
		{Name: "bad name!"},
		{Name: "ok", Node: cloudagent.NodeInfo{CPUCount: -1}},
	} {
		if rec := post(h, "/agent/v1/register", "join-secret", reg); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%+v: %d", reg, rec.Code)
		}
	}
}

func desiredState() domain.HostDesiredState {
	natNet := domain.Network{ID: "net-1", Kind: "nat", CIDR: "10.20.1.0/24", BridgeName: "pfbr-00000001"}
	labNet := domain.Network{ID: "net-2", Kind: "lab", CIDR: "10.66.0.0/24", BridgeName: "pfbr-00000002"}
	vm := domain.Template{Kind: domain.KindVM, Image: domain.Image{Source: "https://example/cirros.img", SHA256: "abc"}}
	ubuntu := domain.Template{Kind: domain.KindVM, StaticNetwork: true, Image: domain.Image{Source: "https://example/u.img", SHA256: "def"}}
	ctr := domain.Template{Kind: domain.KindContainer, Command: []string{"sleep", "infinity"}, Image: domain.Image{Source: "alpine@sha256:1"}}
	return domain.HostDesiredState{Converging: true, Workloads: []domain.DesiredWorkload{
		{Workload: domain.Workload{ID: "w-1", Name: "vm-1", Kind: domain.KindVM, IP: "10.20.1.2", MAC: "52:54:00:00:00:01",
			DesiredState: domain.DesiredRunning, Generation: 2, VCPUs: 1, MemoryMiB: 256, DiskGiB: 1}, Template: vm, Network: natNet},
		{Workload: domain.Workload{ID: "w-2", Name: "vm-2", Kind: domain.KindVM, IP: "10.20.1.3", MAC: "52:54:00:00:00:02",
			DesiredState: domain.DesiredDeleted, Generation: 3}, Template: vm, Network: natNet},
		{Workload: domain.Workload{ID: "w-3", Name: "lab-1", Kind: domain.KindVM, IP: "10.66.0.2", MAC: "52:54:00:00:00:03",
			DesiredState: domain.DesiredStopped, Generation: 1}, Template: ubuntu, Network: labNet},
		{Workload: domain.Workload{ID: "w-4", Name: "ctr-1", Kind: domain.KindContainer, IP: "10.20.1.4", MAC: "52:54:00:00:00:04",
			DesiredState: domain.DesiredRunning, Generation: 1, Spec: domain.WorkloadSpec{Env: map[string]string{"A": "b"}}},
			Template: ctr, Network: natNet},
	}}
}

func TestRenderDesiredState(t *testing.T) {
	resp, err := Render("node-1", desiredState())
	if err != nil {
		t.Fatal(err)
	}
	if resp.SyncIntervalSeconds != ConvergingInterval || len(resp.Workloads) != 4 || len(resp.Networks) != 2 {
		t.Fatalf("response: %+v", resp)
	}

	nat := resp.Networks[0]
	if nat.Gateway != "10.20.1.1" || nat.DHCPSpareStart != "10.20.1.249" || nat.DHCPSpareEnd != "10.20.1.254" {
		t.Errorf("nat network: %+v", nat)
	}
	// Only the running VM gets a reservation: deleted VMs and containers do not.
	if len(nat.Reservations) != 1 || nat.Reservations[0].MAC != "52:54:00:00:00:01" || nat.Reservations[0].IP != "10.20.1.2" {
		t.Errorf("reservations: %+v", nat.Reservations)
	}
	lab := resp.Networks[1]
	if lab.Gateway != "" || lab.DHCPSpareStart != "" || len(lab.Reservations) != 0 {
		t.Errorf("lab networks have no gateway and no DHCP: %+v", lab)
	}

	powers := map[string]string{}
	for _, w := range resp.Workloads {
		powers[w.ID] = w.Power
	}
	if powers["w-1"] != "running" || powers["w-2"] != "absent" || powers["w-3"] != "stopped" {
		t.Errorf("powers: %v", powers)
	}
	if ci := resp.Workloads[0].CloudInit; ci == nil || ci.NetworkConfig != "" || !strings.Contains(ci.MetaData, `"instance-id":"w-1"`) {
		t.Errorf("DHCP VM seed: %+v", ci)
	}
	if ci := resp.Workloads[2].CloudInit; ci == nil || !strings.Contains(ci.NetworkConfig, "10.66.0.2/24") || strings.Contains(ci.NetworkConfig, "routes") {
		t.Errorf("lab VM seed: %+v", ci)
	}
	c := resp.Workloads[3]
	if c.CloudInit != nil || c.Container == nil || c.Container.Env["A"] != "b" || c.Container.Command[0] != "sleep" || c.PrefixLen != 24 {
		t.Errorf("container: %+v", c)
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	a, _ := Render("node-1", desiredState())
	b, _ := Render("node-1", desiredState())
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Fatal("rendering must be deterministic")
	}
}
