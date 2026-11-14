package docker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
)

const digest = "sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f"

// fakeDocker implements the slice of the Engine API the driver uses.
type fakeDocker struct {
	mu         sync.Mutex
	requests   []string
	images     map[string]bool
	containers map[string]map[string]any // name -> create body
	running    map[string]bool
	networks   map[string]map[string]any
	pullError  string
}

func newFakeDocker() *fakeDocker {
	return &fakeDocker{images: map[string]bool{}, containers: map[string]map[string]any{},
		running: map[string]bool{}, networks: map[string]map[string]any{}}
}

func (f *fakeDocker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	body := map[string]any{}
	if r.Body != nil {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
	}
	path := r.URL.Path
	switch {
	case path == "/version":
		_ = json.NewEncoder(w).Encode(map[string]string{"Version": "29.4.2", "ApiVersion": "1.54"})
	case r.Method == "GET" && strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json"):
		if !f.images[strings.TrimSuffix(strings.TrimPrefix(path, "/images/"), "/json")] {
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message":"No such image"}`))
		}
	case path == "/images/create":
		if f.pullError != "" {
			_, _ = w.Write([]byte(`{"status":"Pulling"}` + "\n" + `{"error":"` + f.pullError + `"}` + "\n"))
			return
		}
		f.images[r.URL.Query().Get("fromImage")+"@"+r.URL.Query().Get("tag")] = true
		_, _ = w.Write([]byte(`{"status":"Pulling"}` + "\n" + `{"status":"Done"}` + "\n"))
	case path == "/containers/create":
		name := r.URL.Query().Get("name")
		if _, ok := f.containers[name]; ok {
			w.WriteHeader(409)
			return
		}
		f.containers[name] = body
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"Id":"abc"}`))
	case path == "/containers/json":
		var list []map[string]any
		for name, b := range f.containers {
			state := "exited"
			if f.running[name] {
				state = "running"
			}
			list = append(list, map[string]any{"Id": name, "State": state, "Labels": b["Labels"]})
		}
		_ = json.NewEncoder(w).Encode(list)
	case strings.HasSuffix(path, "/start"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/start")
		if f.running[name] {
			w.WriteHeader(304)
			return
		}
		f.running[name] = true
		w.WriteHeader(204)
	case strings.HasSuffix(path, "/stop") || strings.HasSuffix(path, "/kill"):
		name := strings.TrimPrefix(path, "/containers/")
		name = name[:strings.LastIndex(name, "/")]
		if !f.running[name] {
			w.WriteHeader(409)
			return
		}
		f.running[name] = false
		w.WriteHeader(204)
	case r.Method == "DELETE" && strings.HasPrefix(path, "/containers/"):
		name := strings.TrimPrefix(path, "/containers/")
		if _, ok := f.containers[name]; !ok {
			w.WriteHeader(404)
			return
		}
		delete(f.containers, name)
		delete(f.running, name)
		w.WriteHeader(204)
	case path == "/networks" && r.Method == "GET":
		var list []map[string]any
		for name, b := range f.networks {
			list = append(list, map[string]any{"Id": name, "Name": name, "Labels": b["Labels"]})
		}
		_ = json.NewEncoder(w).Encode(list)
	case path == "/networks/create":
		f.networks[body["Name"].(string)] = body
		w.WriteHeader(201)
	case r.Method == "DELETE" && strings.HasPrefix(path, "/networks/"):
		delete(f.networks, strings.TrimPrefix(path, "/networks/"))
		w.WriteHeader(204)
	default:
		w.WriteHeader(500)
	}
}

func driver(t *testing.T) (*Driver, *fakeDocker) {
	t.Helper()
	fake := newFakeDocker()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return newForTest(srv.URL, srv.Client()), fake
}

func workload() cloudagent.DesiredWorkload {
	return cloudagent.DesiredWorkload{
		ID: "w1", Name: "sleeper", Kind: cloudagent.KindContainer, VCPUs: 1, MemoryMiB: 256,
		IP: "10.30.0.2", MAC: "52:54:00:00:00:02",
		Image:     cloudagent.Image{Source: "docker.io/library/alpine:3.22@" + digest},
		Container: &cloudagent.ContainerSpec{Command: []string{"sleep", "infinity"}, Env: map[string]string{"B": "2", "A": "1"}},
	}
}

var network = cloudagent.DesiredNetwork{ID: "n1", Kind: cloudagent.NetworkNAT, Bridge: "pfbr-00000030", CIDR: "10.30.0.0/24", Gateway: "10.30.0.1"}

func TestLifecycle(t *testing.T) {
	d, fake := driver(t)
	ctx := context.Background()

	if v, err := d.Probe(ctx); err != nil || v != "Docker 29.4.2 (API 1.54)" {
		t.Fatalf("probe %q %v", v, err)
	}
	if err := d.SyncNetworks(ctx, []cloudagent.DesiredNetwork{network}, nil); err != nil {
		t.Fatal(err)
	}
	var steps []string
	if err := d.Create(ctx, workload(), network, func(s string) { steps = append(steps, s) }); err != nil {
		t.Fatal(err)
	}
	if err := d.Create(ctx, workload(), network, func(string) {}); err != nil {
		t.Fatalf("a repeated create must be idempotent: %v", err)
	}
	if err := d.Start(ctx, "w1"); err != nil {
		t.Fatal(err)
	}
	if err := d.Start(ctx, "w1"); err != nil {
		t.Fatalf("starting a running container must succeed: %v", err)
	}
	list, err := d.List(ctx)
	if err != nil || !list["w1"].Running {
		t.Fatalf("list %+v %v", list, err)
	}

	body := fake.containers["pf-w1"]
	host := body["HostConfig"].(map[string]any)
	if body["Image"] != "docker.io/library/alpine@"+digest {
		t.Errorf("image must be referenced by digest: %v", body["Image"])
	}
	if host["CapDrop"].([]any)[0] != "ALL" || host["SecurityOpt"].([]any)[0] != "no-new-privileges:true" {
		t.Errorf("hardening missing: %v", host)
	}
	if host["Memory"].(float64) != 256<<20 || host["NanoCpus"].(float64) != 1e9 || host["PidsLimit"].(float64) != pidsLimit {
		t.Errorf("limits: %v", host)
	}
	if env := body["Env"].([]any); env[0] != "A=1" || env[1] != "B=2" {
		t.Errorf("env must be sorted: %v", env)
	}
	ep := body["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)["pfbr-00000030"].(map[string]any)
	if ep["IPAMConfig"].(map[string]any)["IPv4Address"] != "10.30.0.2" {
		t.Errorf("address: %v", ep)
	}

	if err := d.Stop(ctx, "w1"); err != nil {
		t.Fatal(err)
	}
	if err := d.Kill(ctx, "w1"); err != nil {
		t.Fatalf("killing a stopped container must succeed: %v", err)
	}
	if err := d.Delete(ctx, "w1"); err != nil {
		t.Fatal(err)
	}
	if err := d.Delete(ctx, "w1"); err != nil {
		t.Fatalf("deleting twice must succeed: %v", err)
	}
	if err := d.SyncNetworks(ctx, nil, []string{"pfbr-00000030"}); err != nil || len(fake.networks) != 0 {
		t.Fatalf("network removal: %v %v", err, fake.networks)
	}
}

func TestNetworkKinds(t *testing.T) {
	d, fake := driver(t)
	iso := network
	iso.Kind, iso.Bridge = cloudagent.NetworkIsolated, "pfbr-00000031"
	lab := network
	lab.Kind, lab.Bridge = cloudagent.NetworkLab, "pfbr-00000032"

	err := d.SyncNetworks(context.Background(), []cloudagent.DesiredNetwork{network, iso, lab}, nil)
	if err == nil || !strings.Contains(err.Error(), "lab") {
		t.Fatalf("lab networks must be refused: %v", err)
	}
	if fake.networks["pfbr-00000030"]["Internal"] != false || fake.networks["pfbr-00000031"]["Internal"] != true {
		t.Fatalf("internal flags: %v", fake.networks)
	}
	if _, ok := fake.networks["pfbr-00000032"]; ok {
		t.Fatal("lab network created")
	}
	opts := fake.networks["pfbr-00000030"]["Options"].(map[string]any)
	if opts["com.docker.network.bridge.name"] != "pfbr-00000030" {
		t.Fatalf("bridge name: %v", opts)
	}
}

func TestUnpinnedImagesAndPullErrorsAreReported(t *testing.T) {
	d, fake := driver(t)
	w := workload()
	w.Image.Source = "alpine:latest"
	if err := d.Create(context.Background(), w, network, func(string) {}); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("got %v", err)
	}
	fake.pullError = "manifest unknown"
	if err := d.Create(context.Background(), workload(), network, func(string) {}); err == nil || !strings.Contains(err.Error(), "manifest unknown") {
		t.Fatalf("got %v", err)
	}
}

func TestSplitReference(t *testing.T) {
	cases := map[string]string{
		"docker.io/library/nginx:1.28-alpine@" + digest: "docker.io/library/nginx",
		"registry.local:5000/team/app@" + digest:        "registry.local:5000/team/app",
		"alpine@" + digest:                              "alpine",
	}
	for ref, want := range cases {
		repo, dg, pinned, err := splitReference(ref)
		if err != nil || repo != want || dg != digest || pinned != want+"@"+digest {
			t.Errorf("%s: %s %s %s %v", ref, repo, dg, pinned, err)
		}
	}
}

func TestUsageFrom(t *testing.T) {
	var s statsResponse
	s.CPUStats.CPUUsage.TotalUsage = 300
	s.PreCPUStats.CPUUsage.TotalUsage = 100
	s.CPUStats.SystemUsage = 2000
	s.PreCPUStats.SystemUsage = 1000
	s.CPUStats.OnlineCPUs = 4
	s.MemoryStats.Usage = 300 << 20
	s.MemoryStats.Stats = map[string]uint64{"inactive_file": 100 << 20}

	// 200/1000 of the host's 4 CPUs = 80 % of one CPU; on 2 vCPUs = 40 %.
	u, ok := usageFrom(s, 2)
	if !ok || u.CPUPercent != 40 || u.MemoryUsedMiB != 200 {
		t.Fatalf("got %+v %v", u, ok)
	}
	if _, ok := usageFrom(statsResponse{}, 1); ok {
		t.Fatal("an empty sample has no usage")
	}
}
