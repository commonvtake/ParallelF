package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/commonvtake/parallelf/pkg/ids"
	"github.com/commonvtake/parallelf/pkg/ngsensor"
	"github.com/commonvtake/parallelf/services/netguard/internal/detect"
	"github.com/commonvtake/parallelf/services/netguard/internal/domain"
	"github.com/commonvtake/parallelf/services/netguard/internal/events"
)

var analyst = domain.Actor{Type: "user", ID: "sub-analyst", Name: "analyst"}

func openStore(t *testing.T) (*Postgres, ed25519.PublicKey) {
	t.Helper()
	url := os.Getenv("PF_TEST_NETGUARD_DATABASE_URL")
	if url == "" {
		t.Skip("PF_TEST_NETGUARD_DATABASE_URL is not set; skipping PostgreSQL integration test")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), url, Options{
		Encoder: events.NewEncoder(ids.NewV7, time.Now), NewID: ids.NewV7, Now: time.Now,
		Monitored: []netip.Prefix{netip.MustParsePrefix("10.255.0.0/22"), netip.MustParsePrefix("10.64.0.0/10")}, ScopeKey: priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, pub
}

func admin(t *testing.T) *pgx.Conn {
	t.Helper()
	url := os.Getenv("PF_TEST_ADMIN_DATABASE_URL")
	if url == "" {
		t.Skip("PF_TEST_ADMIN_DATABASE_URL is not set; skipping the cross-service part of the test")
	}
	conn, err := pgx.Connect(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// subnet returns a random /24 of 10.64.0.0/10, so runs sharing one
// database (every earlier run) do not see each other's addresses.
func subnet(t *testing.T) string {
	t.Helper()
	n, _ := rand.Int(rand.Reader, big.NewInt(64*256))
	return fmt.Sprintf("10.%d.%d", 64+n.Int64()/256, n.Int64()%256)
}

var lineCounter int

func raw(parts ...string) string {
	lineCounter++
	sum := sha256.Sum256([]byte(strings.Join(parts, "|") + fmt.Sprint(lineCounter, time.Now().UnixNano())))
	return hex.EncodeToString(sum[:])
}

func sensor(t *testing.T, s *Postgres) domain.Sensor {
	t.Helper()
	x, err := s.RegisterSensor(context.Background(), domain.SensorRegistration{
		RegisterRequest: ngsensor.RegisterRequest{Name: "test-sensor", AgentVersion: "test", Engine: "Suricata test"},
		TokenHash:       []byte(ids.NewV7())[:32],
	})
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func flow(src, dst string, port int, at time.Time) ngsensor.Event {
	return ngsensor.Event{Time: at, Kind: "flow", Interface: "pfbr-test", SrcIP: src, DstIP: dst, DstPort: port, SrcPort: 40000,
		Proto: "tcp", Details: map[string]string{"flow.state": "new"}, RawSHA256: raw("flow", src, dst, fmt.Sprint(port))}
}

func detectAll(t *testing.T, s *Postgres) {
	t.Helper()
	for range 50 {
		res, err := s.Detect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if res.Events == 0 {
			return
		}
	}
	t.Fatal("detection did not catch up")
}

func alertsFor(t *testing.T, s *Postgres, ip string) map[string]domain.Alert {
	t.Helper()
	list, err := s.ListAlerts(context.Background(), domain.AlertFilter{IP: ip, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]domain.Alert{}
	for _, a := range list {
		out[a.Detector] = a
	}
	return out
}

func TestIngestDetectAndFold(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	x := sensor(t, s)
	net := subnet(t)
	attacker, victim := net+".66", net+".10"
	now := time.Now().UTC().Truncate(time.Millisecond)

	batch := []ngsensor.Event{{
		Time: now, Kind: "alert", Interface: "pfbr-test", SrcIP: attacker, DstIP: victim, DstPort: 80, Proto: "tcp",
		Details:   map[string]string{"alert.signature_id": "9100001", "alert.signature": "PARALLELF canary: IDS self-test URI", "alert.severity": "3"},
		RawSHA256: raw("alert"),
	}, {
		Time: now, Kind: "dns", Interface: "pfbr-test", SrcIP: attacker, DstIP: victim, DstPort: 53, Proto: "udp",
		Details: map[string]string{"dns.type": "query", "dns.rrname": "mzxw6ytboi4dsnzrgq3dqmjxgezdgnbvgy3tqojqgezdg.t.exfil.example"}, RawSHA256: raw("dns"),
	}}
	for p := 1; p <= detect.ScanThreshold+5; p++ {
		batch = append(batch, flow(attacker, victim, 1000+p, now))
	}
	req := ngsensor.IngestRequest{Engine: "Suricata test", Interfaces: []string{"pfbr-test"}, Events: batch}
	n, err := s.Ingest(ctx, x, req)
	if err != nil || n != len(batch) {
		t.Fatalf("ingest: %d %v", n, err)
	}
	if again, err := s.Ingest(ctx, x, req); err != nil || again != 0 {
		t.Fatalf("re-delivery must be idempotent: %d %v", again, err)
	}
	detectAll(t, s)

	got := alertsFor(t, s, attacker)
	for _, d := range []string{detect.SuricataPassthrough, detect.PortScan, detect.NewDevice, detect.DNSAnomaly} {
		if _, ok := got[d]; !ok {
			t.Errorf("no %s alert (got %v)", d, got)
		}
	}
	if a := got[detect.PortScan]; a.Severity != "high" || a.Attribution.Source == nil || a.Attribution.Source.Kind != "unknown" {
		t.Errorf("port scan %+v", a)
	}
	if a := got[detect.SuricataPassthrough]; a.RuleID != "sid:9100001" || a.Count != 1 {
		t.Errorf("suricata %+v", a)
	}

	// The same signature again folds into the open alert.
	more := batch[0]
	more.RawSHA256 = raw("alert-again")
	if _, err := s.Ingest(ctx, x, ngsensor.IngestRequest{Events: []ngsensor.Event{more}}); err != nil {
		t.Fatal(err)
	}
	detectAll(t, s)
	if a := alertsFor(t, s, attacker)[detect.SuricataPassthrough]; a.Count != 2 {
		t.Fatalf("not folded: %+v", a)
	}
	full, err := s.GetAlert(ctx, got[detect.SuricataPassthrough].ID)
	if err != nil {
		t.Fatal(err)
	}
	evs, err := s.AlertEvents(ctx, full, 100)
	if err != nil || len(evs) < 2 {
		t.Fatalf("alert events %d %v", len(evs), err)
	}

	assets, err := s.Assets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range assets {
		if a.IP == attacker && a.Party.Kind == "unknown" {
			found = true
		}
	}
	if !found {
		t.Fatal("the attacker is not an asset")
	}
	if _, err := s.Overview(ctx); err != nil {
		t.Fatal(err)
	}
	sensors, err := s.ListSensors(ctx)
	if err != nil || len(sensors) == 0 || sensors[0].Status != "reporting" {
		t.Fatalf("sensors %+v %v", sensors, err)
	}
	if err := s.DeleteSensor(ctx, x.ID, analyst); !errors.Is(err, domain.ErrSensorActive) {
		t.Fatalf("a reporting sensor cannot be removed: %v", err)
	}
}

func TestAttributionFromCloudAndVPNEvents(t *testing.T) {
	s, _ := openStore(t)
	conn := admin(t)
	ctx := context.Background()
	x := sensor(t, s)
	net := subnet(t)
	netID, wlID, devID := ids.NewV7(), ids.NewV7(), ids.NewV7()
	ts := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)
	insert := func(schema, subject, payload string) {
		t.Helper()
		_, err := conn.Exec(ctx, `INSERT INTO `+schema+`.outbox (id, subject, event_type, payload, headers) VALUES ($1::text::uuid, $2, 'test', $3, '{}')`,
			ids.NewV7(), subject, []byte(payload))
		if err != nil {
			t.Fatal(err)
		}
	}
	insert("cloud", "pf.cloud.evt.network.created", fmt.Sprintf(`{"networkId":%q,"name":"lab-net","kind":"lab","cidr":"%s.0/24","createdAt":%q}`, netID, net, ts))
	insert("cloud", "pf.cloud.evt.workload.created", fmt.Sprintf(`{"workloadId":%q,"name":"victim-vm","ip":"%s.5","createdAt":%q}`, wlID, net, ts))
	insert("vpn", "pf.vpn.evt.device.created", fmt.Sprintf(`{"deviceId":%q,"name":"laptop","ownerSubject":"sub-x","ownerName":"alice","address":"10.255.3.%d","createdAt":%q}`,
		devID, time.Now().UnixNano()%250+1, ts))

	for _, src := range []string{"cloud", "vpn"} {
		if _, err := s.Consume(ctx, src); err != nil {
			t.Fatal(err)
		}
		if again, err := s.Consume(ctx, src); err != nil || again.Applied != 0 {
			t.Fatalf("consumption must be exactly once: %+v %v", again, err)
		}
	}

	now := time.Now().UTC()
	if _, err := s.Ingest(ctx, x, ngsensor.IngestRequest{Events: []ngsensor.Event{flow(net+".5", "1.1.1.1", 443, now)}}); err != nil {
		t.Fatal(err)
	}
	detectAll(t, s)
	got := alertsFor(t, s, net+".5")
	egress, ok := got[detect.LabEgress]
	if !ok {
		t.Fatalf("no lab egress alert: %v", got)
	}
	if src := egress.Attribution.Source; src == nil || src.Kind != "workload" || src.EntityID != wlID || src.Name != "victim-vm" {
		t.Fatalf("attribution %+v", egress.Attribution)
	}
	if _, ok := got[detect.NewDevice]; ok {
		t.Fatal("an attributed workload is not a new device")
	}

	// Deleting the workload ends its attribution.
	insert("cloud", "pf.cloud.evt.workload.deleted", fmt.Sprintf(`{"workloadId":%q,"ip":"%s.5","deletedAt":%q}`, wlID, net, time.Now().UTC().Format(time.RFC3339Nano)))
	if _, err := s.Consume(ctx, "cloud"); err != nil {
		t.Fatal(err)
	}
	var open int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM netguard.attributions WHERE entity_id = $1 AND valid_to IS NULL`, wlID).Scan(&open); err != nil || open != 0 {
		t.Fatalf("open attributions %d %v", open, err)
	}
}

func TestTriageIncidentsAndEvidence(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	x := sensor(t, s)
	net := subnet(t)
	src := net + ".77"
	if _, err := s.Ingest(ctx, x, ngsensor.IngestRequest{Events: []ngsensor.Event{flow(src, net+".1", 22, time.Now().UTC())}}); err != nil {
		t.Fatal(err)
	}
	detectAll(t, s)
	alert, ok := alertsFor(t, s, src)[detect.NewDevice]
	if !ok {
		t.Fatal("no new-device alert")
	}

	if _, err := s.ChangeAlert(ctx, alert.ID, domain.AlertChange{Status: domain.AlertAcknowledged}, analyst); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ChangeAlert(ctx, alert.ID, domain.AlertChange{Status: domain.AlertAcknowledged}, analyst); !errors.Is(err, domain.ErrInvalidState) {
		t.Fatalf("acknowledged twice: %v", err)
	}
	sup, err := s.ChangeAlert(ctx, alert.ID, domain.AlertChange{Status: domain.AlertSuppressed, Reason: "lab printer", SuppressFor: time.Hour}, analyst)
	if err != nil || sup.SuppressedUntil == nil {
		t.Fatalf("suppress: %+v %v", sup, err)
	}

	inc, err := s.CreateIncident(ctx, domain.IncidentInput{Title: "Unknown host on " + net + ".0/24", Severity: "medium", AlertIDs: []string{alert.ID}}, analyst)
	if err != nil || inc.AlertCount != 1 {
		t.Fatalf("incident %+v %v", inc, err)
	}
	if _, err := s.CreateIncident(ctx, domain.IncidentInput{Title: "bad link", Severity: "low", AlertIDs: []string{ids.NewV7()}}, analyst); err == nil {
		t.Fatal("linking a missing alert must fail")
	}
	ev, err := s.AddEvidence(ctx, inc.ID, domain.EvidenceInput{Kind: "event", Name: "first flow", Ref: fmt.Sprint(alert.FirstEventID)}, analyst)
	if err != nil || len(ev.SHA256) != 64 || ev.MediaType != "application/json" {
		t.Fatalf("evidence %+v %v", ev, err)
	}
	if _, err := s.AddEvidence(ctx, inc.ID, domain.EvidenceInput{Kind: "note", Name: "triage", Content: []byte("Checked the switch port.")}, analyst); err != nil {
		t.Fatal(err)
	}
	_, content, err := s.EvidenceContent(ctx, inc.ID, ev.ID)
	if err != nil || !strings.Contains(string(content), src) {
		t.Fatalf("content %s %v", content, err)
	}
	if v, err := s.VerifyEvidence(ctx, inc.ID); err != nil || !v.Valid || v.Checked != 2 {
		t.Fatalf("verify %+v %v", v, err)
	}
	if _, err := s.UpdateIncident(ctx, inc.ID, domain.IncidentUpdate{Status: domain.IncidentResolved, Note: "Owner confirmed the device."}, analyst); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddEvidence(ctx, inc.ID, domain.EvidenceInput{Kind: "note", Name: "late", Content: []byte("x")}, analyst); !errors.Is(err, domain.ErrInvalidState) {
		t.Fatalf("a resolved incident takes no evidence: %v", err)
	}
	d, err := s.GetIncident(ctx, inc.ID)
	if err != nil || len(d.Alerts) != 1 || len(d.Evidence) != 2 || len(d.Timeline) < 5 || d.ResolvedAt == nil {
		t.Fatalf("detail %+v %v", d, err)
	}

	if conn := adminOrNil(); conn != "" {
		c := admin(t)
		if _, err := c.Exec(ctx, `UPDATE netguard.evidence SET name = 'tampered' WHERE id = $1::text::uuid`, ev.ID); err == nil ||
			!strings.Contains(err.Error(), "append-only") {
			t.Fatalf("evidence must be append-only: %v", err)
		}
	}
	if v, err := s.VerifyAudit(ctx); err != nil || !v.Valid {
		t.Fatalf("audit %+v %v", v, err)
	}
}

func adminOrNil() string { return os.Getenv("PF_TEST_ADMIN_DATABASE_URL") }

func TestScopes(t *testing.T) {
	s, pub := openStore(t)
	ctx := context.Background()
	sc, err := s.IssueScope(ctx, domain.ScopeInput{Name: "vpn-inventory", CIDRs: []string{"10.255.0.0/24"}, Techniques: []string{"icmp-echo", "tcp-connect"},
		Ports: []int{22, 443}, Duration: "10m", AuthorizationNote: "Owner-approved inventory of the VPN tunnel."}, analyst)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Status != "active" || sc.RatePPS != 20 {
		t.Fatalf("%+v", sc)
	}
	if _, err := s.IssueScope(ctx, domain.ScopeInput{Name: "home-lan", CIDRs: []string{"192.168.1.0/24"}, Techniques: []string{"icmp-echo"},
		AuthorizationNote: "not a ParallelF network"}, analyst); err == nil {
		t.Fatal("a range ParallelF does not own must be refused")
	}
	active, err := s.ActiveScopes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var verified bool
	for _, ss := range active {
		if v, err := ngsensor.Verify(ss, pub, time.Now()); err == nil && v.ID == sc.ID {
			verified = true
		}
	}
	if !verified {
		t.Fatal("the issued scope is not handed out with a valid signature")
	}
	if _, err := s.RevokeScope(ctx, sc.ID, analyst); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeScope(ctx, sc.ID, analyst); !errors.Is(err, domain.ErrInvalidState) {
		t.Fatalf("revoked twice: %v", err)
	}
	active, _ = s.ActiveScopes(ctx)
	for _, ss := range active {
		if v, err := ngsensor.Verify(ss, pub, time.Now()); err == nil && v.ID == sc.ID {
			t.Fatal("a revoked scope is still handed out")
		}
	}
}

func TestPortScanInsideAuthorisedScopeIsInformational(t *testing.T) {
	s, _ := openStore(t)
	ctx := context.Background()
	x := sensor(t, s)
	target := fmt.Sprintf("10.255.2.%d", time.Now().UnixNano()%250+1)
	if _, err := s.IssueScope(ctx, domain.ScopeInput{Name: "scan-test", CIDRs: []string{target + "/32"}, Techniques: []string{"tcp-connect"},
		Ports: []int{22}, Duration: "5m", AuthorizationNote: "Authorised scan in the integration test."}, analyst); err != nil {
		t.Fatal(err)
	}
	scanner := fmt.Sprintf("10.255.1.%d", time.Now().UnixNano()%250+1)
	now := time.Now().UTC()
	var batch []ngsensor.Event
	for p := 1; p <= detect.ScanThreshold; p++ {
		batch = append(batch, flow(scanner, target, 2000+p, now))
	}
	if _, err := s.Ingest(ctx, x, ngsensor.IngestRequest{Events: batch}); err != nil {
		t.Fatal(err)
	}
	detectAll(t, s)
	scan, ok := alertsFor(t, s, target)[detect.PortScan]
	if !ok || scan.Severity != "info" || scan.Details["scope_id"] == "" {
		t.Fatalf("scan %+v", scan)
	}
}
