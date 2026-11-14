package store

// Integration tests against PostgreSQL with the cloud migrations applied.
// They run when PF_TEST_CLOUD_DATABASE_URL is set (pf_cloud runtime role);
// the tamper test also needs PF_TEST_ADMIN_DATABASE_URL (a superuser).

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
	"github.com/commonvtake/parallelf/pkg/ids"
	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
)

type jsonEncoder struct{}

func (jsonEncoder) event(subject string, v any) (domain.OutboxEvent, error) {
	payload, err := json.Marshal(v)
	id := ids.NewV7()
	return domain.OutboxEvent{ID: id, Subject: subject, Type: "test." + subject, Payload: payload,
		Headers: map[string]string{"ce-id": id}}, err
}

func (e jsonEncoder) NodeRegistered(n domain.Node) (domain.OutboxEvent, error) {
	return e.event("node.registered", map[string]string{"node_id": n.ID})
}
func (e jsonEncoder) NodeStatusChanged(n domain.Node, from, to string, _ time.Time) (domain.OutboxEvent, error) {
	return e.event("node.status_changed", map[string]string{"node_id": n.ID, "from": from, "to": to})
}
func (e jsonEncoder) NetworkCreated(n domain.Network) (domain.OutboxEvent, error) {
	return e.event("network.created", map[string]string{"network_id": n.ID})
}
func (e jsonEncoder) NetworkDeleted(n domain.Network, _ string, _ time.Time) (domain.OutboxEvent, error) {
	return e.event("network.deleted", map[string]string{"network_id": n.ID})
}
func (e jsonEncoder) WorkloadCreated(w domain.Workload) (domain.OutboxEvent, error) {
	return e.event("workload.created", map[string]string{"workload_id": w.ID, "ip": w.IP})
}
func (e jsonEncoder) WorkloadStateChanged(w domain.Workload, from string, _ time.Time) (domain.OutboxEvent, error) {
	return e.event("workload.state_changed", map[string]string{"workload_id": w.ID, "from": from, "to": w.State})
}
func (e jsonEncoder) WorkloadDeleted(w domain.Workload, _ time.Time) (domain.OutboxEvent, error) {
	return e.event("workload.deleted", map[string]string{"workload_id": w.ID, "ip": w.IP})
}

var (
	userActor  = domain.Actor{Type: "user", ID: "sub-test", Name: "tester", RequestID: "req-test"}
	agentActor = domain.Actor{Type: "agent"}
)

func openStore(t *testing.T) *Postgres {
	t.Helper()
	url := os.Getenv("PF_TEST_CLOUD_DATABASE_URL")
	if url == "" {
		t.Skip("PF_TEST_CLOUD_DATABASE_URL is not set; skipping PostgreSQL integration test")
	}
	s, err := Open(context.Background(), url, Options{
		Encoder: jsonEncoder{}, NewID: ids.NewV7, Now: time.Now, Overcommit: domain.DefaultOvercommit,
		DefaultQuota: domain.Quota{MaxVCPUs: 100, MaxMemoryMiB: 1 << 20, MaxDiskGiB: 10000, MaxWorkloads: 100},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func randInt(n int64) int64 {
	v, _ := rand.Int(rand.Reader, big.NewInt(n))
	return v.Int64()
}

// randomCIDR returns a /27 that is very unlikely to overlap other tests.
func randomCIDR() string {
	return fmt.Sprintf("10.%d.%d.%d/27", 1+randInt(250), randInt(256), randInt(8)*32)
}

func suffix() string { return fmt.Sprintf("%06d", randInt(1_000_000)) }

func newNetwork(t *testing.T, s *Postgres, project, kind string) domain.Network {
	t.Helper()
	for range 5 {
		n, err := s.CreateNetwork(context.Background(), domain.NetworkInput{
			ProjectID: project, Name: "net-" + suffix(), Kind: kind, CIDR: randomCIDR()}, userActor)
		if errors.Is(err, domain.ErrCIDROverlap) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	t.Fatal("could not find a free CIDR")
	return domain.Network{}
}

func newWorkload(t *testing.T, s *Postgres, project string, n domain.Network, template, flavor string) domain.Workload {
	t.Helper()
	w, err := s.CreateWorkload(context.Background(), domain.WorkloadInput{
		ProjectID: project, Name: "w-" + suffix(), Template: template, Flavor: flavor, NetworkID: n.ID}, userActor)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// registerNode adds a node and makes it the only schedulable one.
func registerNode(t *testing.T, s *Postgres, memMiB int64) (domain.Node, string) {
	t.Helper()
	token := "tok-" + ids.NewV7()
	sum := []byte(token)
	hash := make([]byte, 32)
	copy(hash, sum[len(sum)-32:])
	n, err := s.RegisterNode(context.Background(), domain.NodeRegistration{
		Name: "node-" + suffix(), AgentVersion: "test", TokenHash: hash, KVM: true, Docker: true,
		CPUCount: 4, MemoryMiB: memMiB, DiskGiB: 500,
	}, agentActor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(context.Background(), `UPDATE cloud.nodes SET schedulable = (id = $1::text::uuid)`, n.ID); err != nil {
		t.Fatal(err)
	}
	return n, string(hash)
}

func outboxSubjects(t *testing.T, s *Postgres, workloadID string) []string {
	t.Helper()
	rows, err := s.pool.Query(context.Background(),
		`SELECT subject FROM cloud.outbox WHERE convert_from(payload, 'UTF8')::jsonb->>'workload_id' = $1 ORDER BY created_at, id`, workloadID)
	if err != nil {
		t.Fatal(err)
	}
	subjects, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return subjects
}

func TestNetworksRejectOverlapAndDuplicateNames(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	project := ids.NewV7()
	n := newNetwork(t, s, project, "nat")

	if n.GatewayIP == "" || !strings.HasPrefix(n.BridgeName, "pfbr-") || n.Capacity != 32-2-1-6 {
		t.Fatalf("network %+v", n)
	}
	_, err := s.CreateNetwork(ctx, domain.NetworkInput{ProjectID: ids.NewV7(), Name: "other", Kind: "nat", CIDR: n.CIDR}, userActor)
	if !errors.Is(err, domain.ErrCIDROverlap) {
		t.Fatalf("overlap: %v", err)
	}
	_, err = s.CreateNetwork(ctx, domain.NetworkInput{ProjectID: project, Name: n.Name, Kind: "nat", CIDR: randomCIDR()}, userActor)
	if !errors.Is(err, domain.ErrNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}

	lab := newNetwork(t, s, project, "lab")
	if lab.GatewayIP != "" {
		t.Fatalf("lab networks have no gateway: %+v", lab)
	}

	if err := s.DeleteNetwork(ctx, n.ID, userActor); err != nil {
		t.Fatal(err)
	}
	// The CIDR is free again once the network is deleted.
	if _, err := s.CreateNetwork(ctx, domain.NetworkInput{ProjectID: project, Name: "again-" + suffix(), Kind: "isolated", CIDR: n.CIDR}, userActor); err != nil {
		t.Fatalf("reuse CIDR: %v", err)
	}
}

func TestAdmissionEnforcesQuotaAndReusesAddresses(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	project := ids.NewV7()
	if _, err := s.PutQuota(ctx, domain.Quota{ProjectID: project, MaxVCPUs: 10, MaxMemoryMiB: 512, MaxDiskGiB: 10, MaxWorkloads: 10}, userActor); err != nil {
		t.Fatal(err)
	}
	n := newNetwork(t, s, project, "nat")

	a := newWorkload(t, s, project, n, "cirros", "")
	b := newWorkload(t, s, project, n, "cirros", "")
	if a.IP == b.IP || a.State != domain.StatePending || a.MemoryMiB != 256 || a.TemplateVersion != 1 {
		t.Fatalf("a=%+v b=%+v", a, b)
	}

	_, err := s.CreateWorkload(ctx, domain.WorkloadInput{ProjectID: project, Name: "w-third", Template: "cirros", NetworkID: n.ID}, userActor)
	var quota *domain.QuotaError
	if !errors.As(err, &quota) || quota.Exceeded[0] != "memory_mib" {
		t.Fatalf("quota: %v", err)
	}

	// A workload that was never placed is deleted at once, and its address
	// and quota are free again.
	deleted, err := s.ChangeDesiredState(ctx, a.ID, domain.OpDelete, userActor)
	if err != nil || deleted.State != domain.StateDeleted || deleted.DeletedAt == nil {
		t.Fatalf("delete: %+v %v", deleted, err)
	}
	c := newWorkload(t, s, project, n, "cirros", "")
	if c.IP != a.IP {
		t.Fatalf("address %s not reused (got %s)", a.IP, c.IP)
	}
	if got := outboxSubjects(t, s, a.ID); strings.Join(got, ",") != "workload.created,workload.state_changed,workload.deleted" {
		t.Fatalf("events: %v", got)
	}
	if _, err := s.CreateWorkload(ctx, domain.WorkloadInput{ProjectID: project, Name: b.Name, Template: "cirros", NetworkID: n.ID}, userActor); !errors.Is(err, domain.ErrNameTaken) {
		t.Fatalf("duplicate name: %v", err)
	}
}

func TestPlacementRules(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	project := ids.NewV7()
	lab := newNetwork(t, s, project, "lab")
	nat := newNetwork(t, s, project, "nat")

	cases := []struct {
		template string
		network  domain.Network
		code     string
	}{
		{"alpine-sleeper", lab, "lab_requires_vm"},
		{"cirros", lab, "lab_requires_static_network"},
	}
	for _, tc := range cases {
		_, err := s.CreateWorkload(ctx, domain.WorkloadInput{ProjectID: project, Name: "w-" + suffix(), Template: tc.template, NetworkID: tc.network.ID}, userActor)
		var v *domain.ValidationError
		if !errors.As(err, &v) || v.Code != tc.code {
			t.Errorf("%s on %s: %v", tc.template, tc.network.Kind, err)
		}
	}
	if w := newWorkload(t, s, project, lab, "ubuntu-24.04", ""); w.Kind != domain.KindVM {
		t.Fatalf("ubuntu on lab: %+v", w)
	}

	newWorkload(t, s, project, nat, "cirros", "")
	_, err := s.CreateWorkload(ctx, domain.WorkloadInput{ProjectID: project, Name: "w-" + suffix(), Template: "alpine-sleeper", NetworkID: nat.ID}, userActor)
	var v *domain.ValidationError
	if !errors.As(err, &v) || v.Code != "mixed_kinds" {
		t.Fatalf("mixed kinds: %v", err)
	}
	_, err = s.CreateWorkload(ctx, domain.WorkloadInput{ProjectID: ids.NewV7(), Name: "w-" + suffix(), Template: "cirros", NetworkID: nat.ID}, userActor)
	if !errors.As(err, &v) || v.Code != "project" {
		t.Fatalf("other project's network: %v", err)
	}
	_, err = s.CreateWorkload(ctx, domain.WorkloadInput{ProjectID: project, Name: "w-" + suffix(), Template: "no-such", NetworkID: nat.ID}, userActor)
	if !errors.As(err, &v) || v.Field != "template" {
		t.Fatalf("unknown template: %v", err)
	}
}

func TestConcurrentSchedulingNeverOvercommits(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	node, _ := registerNode(t, s, 2048) // room for exactly two 1 GiB workloads
	project := ids.NewV7()
	n := newNetwork(t, s, project, "nat")

	var workloads []domain.Workload
	for range 6 {
		workloads = append(workloads, newWorkload(t, s, project, n, "cirros", "pf.small"))
	}
	var wg sync.WaitGroup
	for _, w := range workloads {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			if _, err := s.Schedule(ctx, id); err != nil {
				t.Error(err)
			}
		}(w.ID)
	}
	wg.Wait()

	got, err := s.GetNode(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Workloads != 2 || got.Allocated.MemoryMiB != 2048 {
		t.Fatalf("node allocation %+v (workloads %d)", got.Allocated, got.Workloads)
	}
	pending := 0
	for _, w := range workloads {
		cur, _ := s.GetWorkload(ctx, w.ID)
		if cur.State == domain.StatePending {
			pending++
			if !strings.Contains(cur.StatusMessage, "insufficient memory") {
				t.Errorf("pending without reason: %q", cur.StatusMessage)
			}
		}
	}
	if pending != 4 {
		t.Fatalf("pending = %d, want 4", pending)
	}
	for _, w := range workloads {
		_, _ = s.ChangeDesiredState(ctx, w.ID, domain.OpDelete, userActor)
	}
}

func observe(id string, state string, applied int64) cloudagent.ObservedWorkload {
	return cloudagent.ObservedWorkload{ID: id, State: state, AppliedGeneration: applied}
}

func TestSyncDrivesTheLifecycle(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	node, _ := registerNode(t, s, 8192)
	project := ids.NewV7()
	n := newNetwork(t, s, project, "nat")
	w := newWorkload(t, s, project, n, "cirros", "")
	if res, err := s.Schedule(ctx, w.ID); err != nil || res.NodeID != node.ID {
		t.Fatalf("schedule: %+v %v", res, err)
	}

	report := func(obs ...cloudagent.ObservedWorkload) domain.HostDesiredState {
		t.Helper()
		cpu, mem := 5.0, int64(120)
		for i := range obs {
			obs[i].CPUPercent, obs[i].MemoryUsedMiB = &cpu, &mem
		}
		d, err := s.Sync(ctx, node, cloudagent.SyncRequest{AgentVersion: "test", Workloads: obs,
			Node:    cloudagent.NodeInfo{KVM: true, Docker: true, CPUCount: 4, MemoryMiB: 8192, DiskGiB: 500},
			Metrics: &cloudagent.NodeMetrics{CPUPercent: 10, MemoryUsedMiB: 1000, MemoryTotalMiB: 8192, DiskUsedGiB: 1, DiskTotalGiB: 500}})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	state := func() domain.Workload {
		t.Helper()
		cur, err := s.GetWorkload(ctx, w.ID)
		if err != nil {
			t.Fatal(err)
		}
		return cur
	}

	desired := report()
	if len(desired.Workloads) != 1 || desired.Workloads[0].Template.Image.SHA256 == "" || desired.Workloads[0].Network.ID != n.ID || !desired.Converging {
		t.Fatalf("desired %+v", desired)
	}
	report(observe(w.ID, "provisioning", 0))
	if st := state(); st.State != domain.StateProvisioning {
		t.Fatalf("provisioning: %s", st.State)
	}
	report(observe(w.ID, "running", 1))
	if st := state(); st.State != domain.StateRunning || st.ObservedGeneration != 1 {
		t.Fatalf("running: %+v", st)
	}
	points, err := s.WorkloadMetrics(ctx, w.ID, time.Now().Add(-time.Minute))
	if err != nil || len(points) == 0 || points[0].MemoryUsedMiB != 120 {
		t.Fatalf("workload metrics %+v %v", points, err)
	}
	nodePoints, _ := s.NodeMetrics(ctx, node.ID, time.Now().Add(-time.Minute))
	if len(nodePoints) == 0 {
		t.Fatal("node metrics not stored")
	}

	if _, err := s.ChangeDesiredState(ctx, w.ID, domain.OpStart, userActor); !errors.Is(err, domain.ErrInvalidState) {
		t.Fatalf("start while running: %v", err)
	}
	stopped, err := s.ChangeDesiredState(ctx, w.ID, domain.OpStop, userActor)
	if err != nil || stopped.State != domain.StateStopping || stopped.Generation != 2 {
		t.Fatalf("stop: %+v %v", stopped, err)
	}
	report(observe(w.ID, "stopped", 2))
	if st := state(); st.State != domain.StateStopped {
		t.Fatalf("stopped: %s", st.State)
	}

	if _, err := s.ChangeDesiredState(ctx, w.ID, domain.OpDelete, userActor); err != nil {
		t.Fatal(err)
	}
	if d := report(observe(w.ID, "stopped", 2)); len(d.Workloads) != 1 || d.Workloads[0].Workload.DesiredState != domain.DesiredDeleted {
		t.Fatalf("deleting: %+v", d)
	}
	if d := report(observe(w.ID, "absent", 3)); len(d.Workloads) != 0 {
		t.Fatalf("a deleted workload is no longer desired: %+v", d)
	}
	final := state()
	if final.State != domain.StateDeleted || final.DeletedAt == nil {
		t.Fatalf("deleted: %+v", final)
	}
	var allocations int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM cloud.ip_allocations WHERE workload_id = $1::text::uuid`, w.ID).Scan(&allocations)
	if allocations != 0 {
		t.Fatal("address not released")
	}
	events, _ := s.WorkloadEvents(ctx, w.ID, 100)
	if len(events) < 6 {
		t.Fatalf("history too short: %+v", events)
	}
}

func TestErrorAndRetry(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	node, _ := registerNode(t, s, 8192)
	project := ids.NewV7()
	w := newWorkload(t, s, project, newNetwork(t, s, project, "nat"), "cirros", "")
	_, _ = s.Schedule(ctx, w.ID)

	report := cloudagent.SyncRequest{Workloads: []cloudagent.ObservedWorkload{{ID: w.ID, State: "error", Message: "image checksum mismatch"}}}
	if _, err := s.Sync(ctx, node, report); err != nil {
		t.Fatal(err)
	}
	cur, _ := s.GetWorkload(ctx, w.ID)
	if cur.State != domain.StateError || cur.StatusMessage != "image checksum mismatch" {
		t.Fatalf("error: %+v", cur)
	}
	retried, err := s.ChangeDesiredState(ctx, w.ID, domain.OpRetry, userActor)
	if err != nil || retried.State != domain.StateScheduled || retried.Generation != 2 {
		t.Fatalf("retry: %+v %v", retried, err)
	}
	_, _ = s.ChangeDesiredState(ctx, w.ID, domain.OpDelete, userActor)
}

func TestUnresponsiveNodesAndRecovery(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	node, _ := registerNode(t, s, 8192)
	project := ids.NewV7()
	w := newWorkload(t, s, project, newNetwork(t, s, project, "nat"), "cirros", "")
	_, _ = s.Schedule(ctx, w.ID)
	if _, err := s.Sync(ctx, node, cloudagent.SyncRequest{Workloads: []cloudagent.ObservedWorkload{observe(w.ID, "running", 1)}}); err != nil {
		t.Fatal(err)
	}

	changed, err := s.MarkUnresponsiveNodes(ctx, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range changed {
		found = found || n.ID == node.ID
	}
	if !found {
		t.Fatalf("node not marked: %+v", changed)
	}
	cur, _ := s.GetWorkload(ctx, w.ID)
	got, _ := s.GetNode(ctx, node.ID)
	if cur.State != domain.StateUnknown || got.Status != domain.NodeNotReady {
		t.Fatalf("workload %s node %s", cur.State, got.Status)
	}
	if err := s.DeleteNode(ctx, node.ID, userActor); !errors.Is(err, domain.ErrInvalidState) {
		t.Fatalf("a node with workloads cannot be removed: %v", err)
	}

	// The node reports again: it is READY and the workload RUNNING.
	if _, err := s.Sync(ctx, node, cloudagent.SyncRequest{Workloads: []cloudagent.ObservedWorkload{observe(w.ID, "running", 1)}}); err != nil {
		t.Fatal(err)
	}
	cur, _ = s.GetWorkload(ctx, w.ID)
	got, _ = s.GetNode(ctx, node.ID)
	if cur.State != domain.StateRunning || got.Status != domain.NodeReady {
		t.Fatalf("after recovery: workload %s node %s", cur.State, got.Status)
	}
	_, _ = s.ChangeDesiredState(ctx, w.ID, domain.OpDelete, userActor)
}

func TestNodeCredentialAndReRegistration(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	node, hash := registerNode(t, s, 4096)

	got, err := s.AuthenticateNode(ctx, []byte(hash))
	if err != nil || got.ID != node.ID {
		t.Fatalf("authenticate: %+v %v", got, err)
	}
	if _, err := s.AuthenticateNode(ctx, make([]byte, 32)); !errors.Is(err, domain.ErrUnauthorizedNode) {
		t.Fatalf("unknown credential: %v", err)
	}
	again, err := s.RegisterNode(ctx, domain.NodeRegistration{Name: node.Name, TokenHash: []byte(ids.NewV7()[4:])}, agentActor)
	if err != nil || again.ID != node.ID {
		t.Fatalf("re-register keeps the id: %+v %v", again, err)
	}
	if _, err := s.AuthenticateNode(ctx, []byte(hash)); !errors.Is(err, domain.ErrUnauthorizedNode) {
		t.Fatal("the old credential must stop working")
	}
}

func TestAuditTrailIsAppendOnlyAndVerifiable(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()
	project := ids.NewV7()
	newNetwork(t, s, project, "nat")

	v, err := s.VerifyAudit(ctx)
	if err != nil || !v.Valid || v.Entries == 0 {
		t.Fatalf("verify: %+v %v", v, err)
	}
	entries, err := s.ListAudit(ctx, domain.AuditFilter{Limit: 1})
	if err != nil || len(entries) != 1 || entries[0].Action != "cloud.networks.create" || entries[0].ActorID != userActor.ID {
		t.Fatalf("latest entry %+v %v", entries, err)
	}

	if _, err := s.pool.Exec(ctx, `UPDATE cloud.audit_log SET outcome = 'failed' WHERE seq = $1`, entries[0].Seq); err == nil {
		t.Fatal("the runtime role must not be able to change audit entries")
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM cloud.audit_log WHERE seq = $1`, entries[0].Seq); err == nil {
		t.Fatal("the runtime role must not be able to delete audit entries")
	}

	admin := os.Getenv("PF_TEST_ADMIN_DATABASE_URL")
	if admin == "" {
		t.Log("PF_TEST_ADMIN_DATABASE_URL not set; skipping the tamper-detection part")
		return
	}
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tamper := func(outcome string) {
		t.Helper()
		_, err := conn.Exec(ctx, `
			ALTER TABLE cloud.audit_log DISABLE TRIGGER audit_log_no_update_or_delete;
			UPDATE cloud.audit_log SET outcome = '`+outcome+`' WHERE seq = `+fmt.Sprint(entries[0].Seq)+`;
			ALTER TABLE cloud.audit_log ENABLE TRIGGER audit_log_no_update_or_delete;`)
		if err != nil {
			t.Fatal(err)
		}
	}
	tamper("denied")
	v, err = s.VerifyAudit(ctx)
	tamper("success") // restore, so later runs start from an intact chain
	if err != nil || v.Valid || v.FirstInvalidSeq != entries[0].Seq {
		t.Fatalf("tampering not detected: %+v %v", v, err)
	}
	if v, _ := s.VerifyAudit(ctx); !v.Valid {
		t.Fatal("restoring the row must make the chain valid again")
	}
}
