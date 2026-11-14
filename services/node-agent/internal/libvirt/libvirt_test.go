package libvirt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
)

// fakeRunner answers virsh/qemu-img/genisoimage calls from a script and
// records every command line.
type fakeRunner struct {
	mu       sync.Mutex
	calls    []string
	answers  map[string]string // command prefix -> stdout
	failures map[string]string // command prefix -> error
	info     string            // qemu-img info JSON
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := strings.TrimSpace(name + " " + strings.Join(stripURI(args), " "))
	f.calls = append(f.calls, line)
	for prefix, msg := range f.failures {
		if strings.HasPrefix(line, prefix) {
			return nil, errors.New(msg)
		}
	}
	// Programs that write files.
	switch name {
	case "qemu-img":
		if len(args) > 0 && args[0] == "create" {
			_ = os.WriteFile(args[len(args)-2], []byte("overlay"), 0o644)
		}
		if len(args) > 0 && args[0] == "info" {
			return []byte(f.info), nil
		}
	case "genisoimage":
		for i, a := range args {
			if a == "-output" {
				_ = os.WriteFile(args[i+1], []byte("iso"), 0o644)
			}
		}
	}
	// Longest matching prefix wins.
	best := ""
	for prefix := range f.answers {
		if strings.HasPrefix(line, prefix) && len(prefix) > len(best) {
			best = prefix
		}
	}
	return []byte(f.answers[best]), nil
}

func stripURI(args []string) []string {
	if len(args) >= 2 && args[0] == "-c" {
		return args[2:]
	}
	return args
}

func (f *fakeRunner) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

const id = "01900000-0000-7000-8000-0000000000a1"

func workload() cloudagent.DesiredWorkload {
	return cloudagent.DesiredWorkload{
		ID: id, Name: "web-1", Kind: cloudagent.KindVM, Generation: 1, Power: cloudagent.PowerRunning,
		VCPUs: 2, MemoryMiB: 512, DiskGiB: 1, MAC: "52:54:00:aa:bb:01", IP: "10.20.1.2", PrefixLen: 24,
		CloudInit: &cloudagent.CloudInit{MetaData: "{}\n", UserData: "#cloud-config\n{}\n"},
	}
}

func TestDomainDocument(t *testing.T) {
	doc, err := domainDocument(workload(), "pfbr-00000001", "/d/disk.qcow2", "/d/seed.iso", "/d/console.log")
	if err != nil {
		t.Fatal(err)
	}
	var parsed domainXML
	if err := xml.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("not valid XML: %v\n%s", err, doc)
	}
	s := string(doc)
	for _, want := range []string{
		`<domain type="kvm">`, `<name>pf-` + id + `</name>`, `<uuid>` + id + `</uuid>`,
		`<memory unit="MiB">512</memory>`, `<vcpu>2</vcpu>`, `machine="pc"`,
		`<source file="/d/disk.qcow2"></source>`, `<target dev="vda" bus="virtio"></target>`,
		`device="cdrom"`, `<readonly></readonly>`, `<mac address="52:54:00:aa:bb:01"></mac>`,
		`<source network="pfbr-00000001"></source>`, `<log file="/d/console.log" append="off"></log>`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("domain XML lacks %s", want)
		}
	}
	if strings.Contains(s, "hostdev") || strings.Contains(s, "filesystem") {
		t.Error("no host devices or shared folders may be attached")
	}
}

func TestDomainDocumentEscapesValues(t *testing.T) {
	w := workload()
	w.Name = `x"><devices><hostdev/>`
	doc, err := domainDocument(w, "pfbr-00000001", "/d/disk", "/d/seed", "/d/log")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc), "<hostdev") {
		t.Fatal("a value changed the document structure")
	}
}

func TestNetworkDocuments(t *testing.T) {
	base := cloudagent.DesiredNetwork{ID: "n", Bridge: "pfbr-00000001", CIDR: "10.20.1.0/24", Gateway: "10.20.1.1",
		DHCPSpareStart: "10.20.1.249", DHCPSpareEnd: "10.20.1.254",
		Reservations: []cloudagent.DHCPReservation{{MAC: "52:54:00:aa:bb:01", IP: "10.20.1.2", Name: "web-1"}}}

	nat := base
	nat.Kind = cloudagent.NetworkNAT
	doc, _ := networkDocument(nat)
	for _, want := range []string{`<forward mode="nat">`, `<ip address="10.20.1.1" prefix="24">`,
		`<range start="10.20.1.249" end="10.20.1.254">`, `<host mac="52:54:00:aa:bb:01" name="web-1" ip="10.20.1.2">`} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("nat lacks %s:\n%s", want, doc)
		}
	}

	iso := base
	iso.Kind = cloudagent.NetworkIsolated
	doc, _ = networkDocument(iso)
	if strings.Contains(string(doc), "<forward") || !strings.Contains(string(doc), "<ip ") {
		t.Errorf("isolated network must have an address and no forwarding:\n%s", doc)
	}

	lab := cloudagent.DesiredNetwork{ID: "n", Bridge: "pfbr-00000002", CIDR: "10.66.0.0/24", Kind: cloudagent.NetworkLab}
	doc, _ = networkDocument(lab)
	if strings.Contains(string(doc), "<forward") || strings.Contains(string(doc), "<ip") || strings.Contains(string(doc), "dhcp") {
		t.Errorf("lab network must be a bare bridge:\n%s", doc)
	}

	if _, err := networkDocument(cloudagent.DesiredNetwork{Kind: "public"}); err == nil {
		t.Error("unknown kinds must be refused")
	}
}

func TestReservationsRoundTrip(t *testing.T) {
	n := cloudagent.DesiredNetwork{ID: "n", Kind: cloudagent.NetworkNAT, Bridge: "pfbr-1", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1",
		Reservations: []cloudagent.DHCPReservation{{MAC: "52:54:00:00:00:01", IP: "10.0.0.2", Name: "a"}}}
	doc, _ := networkDocument(n)
	got, err := parseReservations(doc)
	if err != nil || len(got) != 1 || got[0] != n.Reservations[0] {
		t.Fatalf("got %+v %v", got, err)
	}
}

func TestListParsesVirsh(t *testing.T) {
	r := &fakeRunner{answers: map[string]string{
		"virsh list --all --name": "pf-a\npf-b\nunrelated-vm\n\n",
		"virsh list --name":       "pf-a\nunrelated-vm\n",
	}}
	got, err := New("qemu:///system", t.TempDir(), r).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got["a"].Running || got["b"].Running {
		t.Fatalf("got %+v", got)
	}
}

func TestUsageComputesCPUPercentFromDeltas(t *testing.T) {
	r := &fakeRunner{answers: map[string]string{
		"virsh domstats": "Domain: 'pf-x'\n  cpu.time=1000000000\n  balloon.available=262144\n  balloon.unused=131072\n",
	}}
	d := New("qemu:///system", t.TempDir(), r)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return t0 }
	if _, ok := d.Usage(context.Background(), "x", 2); ok {
		t.Fatal("the first sample has no delta")
	}
	r.answers["virsh domstats"] = "  cpu.time=2000000000\n  balloon.available=262144\n  balloon.unused=131072\n"
	d.now = func() time.Time { return t0.Add(2 * time.Second) }
	u, ok := d.Usage(context.Background(), "x", 2)
	// 1 s of CPU over 2 s of wall time on 2 vCPUs = 25 %.
	if !ok || u.CPUPercent != 25 || u.MemoryUsedMiB != 128 {
		t.Fatalf("got %+v %v", u, ok)
	}
}

func TestSyncNetworksDefinesStartsAndReconcilesReservations(t *testing.T) {
	r := &fakeRunner{answers: map[string]string{
		"virsh net-list --all --name": "default\npfbr-00000002\npfbr-0000dead\n",
		"virsh net-list --name":       "pfbr-00000002\npfbr-0000dead\n",
		"virsh net-dumpxml --inactive pfbr-00000002": `<network><name>pfbr-00000002</name><ip address="10.0.2.1" prefix="24"><dhcp>
			<host mac="52:54:00:00:00:09" name="gone" ip="10.0.2.9"/></dhcp></ip></network>`,
		"virsh net-dumpxml --inactive pfbr-00000001": `<network><name>pfbr-00000001</name></network>`,
	}}
	d := New("qemu:///system", t.TempDir(), r)
	desired := []cloudagent.DesiredNetwork{
		{ID: "n1", Kind: cloudagent.NetworkNAT, Bridge: "pfbr-00000001", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1"},
		{ID: "n2", Kind: cloudagent.NetworkIsolated, Bridge: "pfbr-00000002", CIDR: "10.0.2.0/24", Gateway: "10.0.2.1",
			Reservations: []cloudagent.DHCPReservation{{MAC: "52:54:00:00:00:02", IP: "10.0.2.2", Name: "vm"}}},
	}
	if err := d.SyncNetworks(context.Background(), desired, []string{"pfbr-0000dead", "default"}); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(r.callList(), "\n")
	for _, want := range []string{
		"virsh net-define " + filepath.Join(d.dataDir, "networks", "pfbr-00000001.xml"),
		"virsh net-start pfbr-00000001", "virsh net-autostart pfbr-00000001",
		`virsh net-update pfbr-00000002 delete ip-dhcp-host <host mac="52:54:00:00:00:09" name="gone" ip="10.0.2.9"></host> --live --config`,
		`virsh net-update pfbr-00000002 add ip-dhcp-host <host mac="52:54:00:00:00:02" name="vm" ip="10.0.2.2"></host> --live --config`,
		"virsh net-destroy pfbr-0000dead", "virsh net-undefine pfbr-0000dead",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing call: %s\ncalls:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "net-start pfbr-00000002") || strings.Contains(calls, "destroy default") {
		t.Errorf("unexpected call:\n%s", calls)
	}
}

func imageServer(t *testing.T, body []byte) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(body)
	return srv, hex.EncodeToString(sum[:])
}

func TestCreateRunsEveryStepAndIsResumable(t *testing.T) {
	body := []byte("qcow2-image-bytes")
	srv, sum := imageServer(t, body)
	r := &fakeRunner{info: `{"format":"qcow2","virtual-size":2147483648}`}
	dir := t.TempDir()
	d := New("qemu:///system", dir, r)
	d.http = srv.Client()

	w := workload()
	w.Image = cloudagent.Image{Source: srv.URL + "/cirros.img", SHA256: sum}
	net := cloudagent.DesiredNetwork{Bridge: "pfbr-00000001"}
	var steps []string
	if err := d.Create(context.Background(), w, net, func(s string) { steps = append(steps, s) }); err != nil {
		t.Fatal(err)
	}

	base := filepath.Join(dir, "images", sum+".qcow2")
	if got, _ := os.ReadFile(base); string(got) != string(body) {
		t.Fatal("base image not stored under its digest")
	}
	inst := filepath.Join(dir, "instances", id)
	calls := strings.Join(r.callList(), "\n")
	for _, want := range []string{
		"qemu-img info --output=json " + base,
		// The image is 2 GiB virtually, larger than the 1 GiB flavor disk.
		"qemu-img create -q -f qcow2 -F qcow2 -b " + base + " " + filepath.Join(inst, "disk.qcow2.partial") + " 2G",
		"genisoimage -quiet -output " + filepath.Join(inst, "seed.iso.partial") + " -volid cidata",
		"virsh define " + filepath.Join(inst, "domain.xml"),
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing call: %s\ncalls:\n%s", want, calls)
		}
	}
	if _, err := os.Stat(filepath.Join(inst, "seed", "network-config")); !errors.Is(err, os.ErrNotExist) {
		t.Error("network-config must only be written for static addressing")
	}

	// A second Create (after an interruption) neither downloads nor
	// recreates the disk.
	r.mu.Lock()
	r.calls = nil
	r.mu.Unlock()
	if err := d.Create(context.Background(), w, net, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if calls := strings.Join(r.callList(), "\n"); strings.Contains(calls, "qemu-img create") {
		t.Errorf("disk recreated:\n%s", calls)
	}
}

func TestImageChecksumMismatchIsRejected(t *testing.T) {
	srv, _ := imageServer(t, []byte("tampered"))
	d := New("qemu:///system", t.TempDir(), &fakeRunner{info: `{"format":"qcow2"}`})
	d.http = srv.Client()
	w := workload()
	w.Image = cloudagent.Image{Source: srv.URL + "/x.img", SHA256: strings.Repeat("0", 64)}

	err := d.Create(context.Background(), w, cloudagent.DesiredNetwork{}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("got %v", err)
	}
	entries, _ := os.ReadDir(filepath.Join(d.dataDir, "images"))
	instances, _ := os.ReadDir(filepath.Join(d.dataDir, "instances"))
	if len(entries) != 0 || len(instances) != 0 {
		t.Fatalf("a failed creation must leave nothing behind: %v %v", entries, instances)
	}
}

func TestImagesWithBackingFilesAreRejected(t *testing.T) {
	srv, sum := imageServer(t, []byte("img"))
	d := New("qemu:///system", t.TempDir(), &fakeRunner{info: `{"format":"qcow2","backing-filename":"/etc/shadow"}`})
	d.http = srv.Client()
	w := workload()
	w.Image = cloudagent.Image{Source: srv.URL + "/x.img", SHA256: sum}

	err := d.Create(context.Background(), w, cloudagent.DesiredNetwork{}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "backing file") {
		t.Fatalf("got %v", err)
	}
}

func TestPlainHTTPImagesAreRejected(t *testing.T) {
	d := New("qemu:///system", t.TempDir(), &fakeRunner{})
	w := workload()
	w.Image = cloudagent.Image{Source: "http://example.com/x.img", SHA256: strings.Repeat("a", 64)}
	if err := d.Create(context.Background(), w, cloudagent.DesiredNetwork{}, func(string) {}); err == nil {
		t.Fatal("http must be refused")
	}
}

func TestDeleteRemovesDefinitionAndFiles(t *testing.T) {
	r := &fakeRunner{answers: map[string]string{
		"virsh list --all --name": "pf-" + id + "\n",
		"virsh list --name":       "pf-" + id + "\n",
	}}
	d := New("qemu:///system", t.TempDir(), r)
	inst := filepath.Join(d.dataDir, "instances", id)
	_ = os.MkdirAll(inst, 0o755)

	if err := d.Delete(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(r.callList(), "\n")
	if !strings.Contains(calls, "virsh destroy pf-"+id) || !strings.Contains(calls, "virsh undefine pf-"+id) {
		t.Fatalf("calls:\n%s", calls)
	}
	if _, err := os.Stat(inst); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("instance directory not removed")
	}
	if err := d.Delete(context.Background(), "../etc"); err == nil {
		t.Fatal("path traversal in ids must be refused")
	}
}

func TestParseVersion(t *testing.T) {
	out := "Compiled against library: libvirt 12.0.0\nUsing library: libvirt 12.0.0\nUsing API: QEMU 12.0.0\nRunning hypervisor: QEMU 10.2.1\n"
	if got := parseVersion(out); got != "libvirt 12.0.0, QEMU 10.2.1" {
		t.Fatalf("got %q", got)
	}
}

func TestSizeArg(t *testing.T) {
	if got := sizeArg(10, 3<<30); got != "10G" {
		t.Errorf("got %s", got)
	}
	if got := sizeArg(1, 3758096384); got != "4G" {
		t.Errorf("3.5 GiB image must round up: %s", got)
	}
}
