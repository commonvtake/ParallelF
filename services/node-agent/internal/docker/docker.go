// Package docker runs container workloads with Docker Engine, through its
// HTTP API on the local Unix socket.
//
// Containers are created with every capability dropped (the template adds
// back what it needs), no-new-privileges, CPU, memory and PID limits, and a
// fixed address on a Docker bridge network created for the ParallelF
// network. Only containers and networks carrying the io.parallelf labels
// are ever touched.
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
	"github.com/commonvtake/parallelf/services/node-agent/internal/runtime"
)

// Labels set on managed objects.
const (
	LabelManaged    = "io.parallelf.managed"
	LabelWorkloadID = "io.parallelf.workload_id"
	LabelName       = "io.parallelf.workload_name"
	LabelNetworkID  = "io.parallelf.network_id"
	pidsLimit       = 512
)

// Driver implements runtime.Runtime for containers.
type Driver struct {
	base string
	http *http.Client
}

// New returns a driver for the Docker daemon at the Unix socket path.
func New(socket string) *Driver {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	return &Driver{base: "http://docker", http: &http.Client{Transport: transport}}
}

// newForTest points the driver at an ordinary HTTP server.
func newForTest(base string, client *http.Client) *Driver { return &Driver{base: base, http: client} }

// apiError is a non-2xx answer from the daemon.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string { return fmt.Sprintf("docker: %d %s", e.Status, e.Message) }

func statusIs(err error, codes ...int) bool {
	var e *apiError
	if !errors.As(err, &e) {
		return false
	}
	for _, c := range codes {
		if e.Status == c {
			return true
		}
	}
	return false
}

func (d *Driver) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	u := d.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		var e struct {
			Message string `json:"message"`
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = json.Unmarshal(raw, &e)
		return &apiError{Status: resp.StatusCode, Message: e.Message}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func labelFilter(label string) url.Values {
	raw, _ := json.Marshal(map[string][]string{"label": {label}})
	return url.Values{"filters": {string(raw)}}
}

// Kind implements runtime.Runtime.
func (d *Driver) Kind() string { return cloudagent.KindContainer }

// Probe pings the daemon and returns its version.
func (d *Driver) Probe(ctx context.Context) (string, error) {
	var v struct {
		Version    string `json:"Version"`
		APIVersion string `json:"ApiVersion"`
	}
	if err := d.do(ctx, http.MethodGet, "/version", nil, nil, &v); err != nil {
		return "", fmt.Errorf("%w: %v", runtime.ErrUnavailable, err)
	}
	return "Docker " + v.Version + " (API " + v.APIVersion + ")", nil
}

// ContainerName is the Docker name of a workload's container.
func ContainerName(id string) string { return "pf-" + id }

type containerSummary struct {
	ID     string            `json:"Id"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

// List implements runtime.Runtime.
func (d *Driver) List(ctx context.Context) (map[string]runtime.Instance, error) {
	q := labelFilter(LabelWorkloadID)
	q.Set("all", "1")
	var list []containerSummary
	if err := d.do(ctx, http.MethodGet, "/containers/json", q, nil, &list); err != nil {
		return nil, err
	}
	out := map[string]runtime.Instance{}
	for _, c := range list {
		id := c.Labels[LabelWorkloadID]
		if id == "" {
			continue
		}
		out[id] = runtime.Instance{ID: id, Running: c.State == "running"}
	}
	return out, nil
}

// splitReference turns "registry/repo:tag@sha256:..." into the pull
// parameters and the reference the container is created from. Only
// digest-pinned references are accepted.
func splitReference(ref string) (repo, digest, pinned string, err error) {
	name, digest, ok := strings.Cut(ref, "@")
	if !ok || !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+64 {
		return "", "", "", fmt.Errorf("container image %q is not pinned by digest", ref)
	}
	repo = name
	// Drop a tag, but not a registry port ("host:5000/repo").
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		repo = name[:i]
	}
	return repo, digest, repo + "@" + digest, nil
}

// pull fetches the image unless it is present.
func (d *Driver) pull(ctx context.Context, ref string, progress runtime.Progress) (string, error) {
	repo, digest, pinned, err := splitReference(ref)
	if err != nil {
		return "", err
	}
	if err := d.do(ctx, http.MethodGet, "/images/"+pinned+"/json", nil, nil, nil); err == nil {
		return pinned, nil
	} else if !statusIs(err, http.StatusNotFound) {
		return "", err
	}
	progress("pulling image")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		d.base+"/images/create?"+url.Values{"fromImage": {repo}, "tag": {digest}}.Encode(), nil)
	if err != nil {
		return "", err
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("docker pull: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return "", fmt.Errorf("docker pull: %d %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	// The body is a stream of JSON progress messages; errors arrive in it.
	dec := json.NewDecoder(resp.Body)
	for {
		var msg struct {
			Error string `json:"error"`
		}
		if err := dec.Decode(&msg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return "", fmt.Errorf("docker pull: %w", err)
		}
		if msg.Error != "" {
			return "", fmt.Errorf("docker pull: %s", msg.Error)
		}
	}
	return pinned, nil
}

type createBody struct {
	Image            string            `json:"Image"`
	Cmd              []string          `json:"Cmd,omitempty"`
	Env              []string          `json:"Env,omitempty"`
	Hostname         string            `json:"Hostname"`
	Labels           map[string]string `json:"Labels"`
	HostConfig       hostConfig        `json:"HostConfig"`
	NetworkingConfig networkingConfig  `json:"NetworkingConfig"`
}

type hostConfig struct {
	NanoCPUs      int64             `json:"NanoCpus"`
	Memory        int64             `json:"Memory"`
	MemorySwap    int64             `json:"MemorySwap"`
	PidsLimit     int64             `json:"PidsLimit"`
	CapDrop       []string          `json:"CapDrop"`
	CapAdd        []string          `json:"CapAdd,omitempty"`
	SecurityOpt   []string          `json:"SecurityOpt"`
	NetworkMode   string            `json:"NetworkMode"`
	RestartPolicy map[string]string `json:"RestartPolicy"`
	LogConfig     logConfig         `json:"LogConfig"`
}

type logConfig struct {
	Type   string            `json:"Type"`
	Config map[string]string `json:"Config"`
}

type networkingConfig struct {
	EndpointsConfig map[string]endpoint `json:"EndpointsConfig"`
}

type endpoint struct {
	IPAMConfig struct {
		IPv4Address string `json:"IPv4Address"`
	} `json:"IPAMConfig"`
	MacAddress string `json:"MacAddress,omitempty"`
}

func containerBody(w cloudagent.DesiredWorkload, image, network string) createBody {
	env := make([]string, 0, len(w.Container.Env))
	for k, v := range w.Container.Env {
		env = append(env, k+"="+v)
	}
	sort.Strings(env)
	ep := endpoint{MacAddress: w.MAC}
	ep.IPAMConfig.IPv4Address = w.IP
	memory := int64(w.MemoryMiB) << 20
	return createBody{
		Image: image, Cmd: w.Container.Command, Env: env, Hostname: w.Name,
		Labels: map[string]string{LabelManaged: "true", LabelWorkloadID: w.ID, LabelName: w.Name},
		HostConfig: hostConfig{
			NanoCPUs: int64(w.VCPUs) * 1_000_000_000, Memory: memory, MemorySwap: memory, PidsLimit: pidsLimit,
			CapDrop: []string{"ALL"}, CapAdd: w.Container.CapAdd, SecurityOpt: []string{"no-new-privileges:true"},
			NetworkMode: network,
			// The agent restarts containers itself when they should run, so
			// Docker never resurrects one the control plane stopped.
			RestartPolicy: map[string]string{"Name": "no"},
			LogConfig:     logConfig{Type: "json-file", Config: map[string]string{"max-size": "10m", "max-file": "2"}},
		},
		NetworkingConfig: networkingConfig{EndpointsConfig: map[string]endpoint{network: ep}},
	}
}

// Create implements runtime.Runtime.
func (d *Driver) Create(ctx context.Context, w cloudagent.DesiredWorkload, network cloudagent.DesiredNetwork, progress runtime.Progress) error {
	if w.Container == nil {
		return errors.New("container workload has no container spec")
	}
	if network.Kind == cloudagent.NetworkLab {
		return errors.New("containers may not join lab networks")
	}
	image, err := d.pull(ctx, w.Image.Source, progress)
	if err != nil {
		return err
	}
	progress("creating container")
	q := url.Values{"name": {ContainerName(w.ID)}}
	err = d.do(ctx, http.MethodPost, "/containers/create", q, containerBody(w, image, network.Bridge), nil)
	if statusIs(err, http.StatusConflict) {
		return nil // already exists (an earlier attempt got this far)
	}
	return err
}

// Start implements runtime.Runtime.
func (d *Driver) Start(ctx context.Context, id string) error {
	err := d.do(ctx, http.MethodPost, "/containers/"+ContainerName(id)+"/start", nil, nil, nil)
	if statusIs(err, http.StatusNotModified) {
		return nil
	}
	return err
}

// Stop implements runtime.Runtime (SIGTERM, then SIGKILL after 10 s).
func (d *Driver) Stop(ctx context.Context, id string) error {
	err := d.do(ctx, http.MethodPost, "/containers/"+ContainerName(id)+"/stop", url.Values{"t": {"10"}}, nil, nil)
	if statusIs(err, http.StatusNotModified, http.StatusNotFound) {
		return nil
	}
	return err
}

// Kill implements runtime.Runtime.
func (d *Driver) Kill(ctx context.Context, id string) error {
	err := d.do(ctx, http.MethodPost, "/containers/"+ContainerName(id)+"/kill", nil, nil, nil)
	if statusIs(err, http.StatusConflict, http.StatusNotFound) {
		return nil // not running
	}
	return err
}

// Delete implements runtime.Runtime.
func (d *Driver) Delete(ctx context.Context, id string) error {
	err := d.do(ctx, http.MethodDelete, "/containers/"+ContainerName(id), url.Values{"force": {"1"}, "v": {"1"}}, nil, nil)
	if statusIs(err, http.StatusNotFound) {
		return nil
	}
	return err
}

type statsResponse struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs  uint64 `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
}

// Usage implements runtime.Runtime from one stats snapshot (Docker fills
// precpu_stats with the previous second's counters).
func (d *Driver) Usage(ctx context.Context, id string, vcpus int) (runtime.Usage, bool) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var s statsResponse
	if err := d.do(ctx, http.MethodGet, "/containers/"+ContainerName(id)+"/stats", url.Values{"stream": {"false"}}, nil, &s); err != nil {
		return runtime.Usage{}, false
	}
	return usageFrom(s, vcpus)
}

func usageFrom(s statsResponse, vcpus int) (runtime.Usage, bool) {
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPUStats.SystemUsage) - float64(s.PreCPUStats.SystemUsage)
	if sysDelta <= 0 || cpuDelta < 0 || s.CPUStats.OnlineCPUs == 0 || vcpus < 1 {
		return runtime.Usage{}, false
	}
	// Docker's formula gives percent of one host CPU per CPU used; divide
	// by the workload's vCPUs to express it against its own allocation.
	pct := cpuDelta / sysDelta * float64(s.CPUStats.OnlineCPUs) * 100 / float64(vcpus)
	if pct > 100 {
		pct = 100
	}
	mem := s.MemoryStats.Usage
	if cache := s.MemoryStats.Stats["inactive_file"]; cache <= mem {
		mem -= cache
	}
	return runtime.Usage{CPUPercent: pct, MemoryUsedMiB: int64(mem >> 20)}, true
}

type networkSummary struct {
	ID     string            `json:"Id"`
	Name   string            `json:"Name"`
	Labels map[string]string `json:"Labels"`
}

// ListNetworks implements runtime.Runtime.
func (d *Driver) ListNetworks(ctx context.Context) ([]string, error) {
	var list []networkSummary
	if err := d.do(ctx, http.MethodGet, "/networks", labelFilter(LabelNetworkID), nil, &list); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, n := range list {
		out = append(out, n.Name)
	}
	return out, nil
}

type networkCreate struct {
	Name     string            `json:"Name"`
	Driver   string            `json:"Driver"`
	Internal bool              `json:"Internal"`
	IPAM     ipam              `json:"IPAM"`
	Options  map[string]string `json:"Options"`
	Labels   map[string]string `json:"Labels"`
}

type ipam struct {
	Driver string       `json:"Driver"`
	Config []ipamConfig `json:"Config"`
}

type ipamConfig struct {
	Subnet  string `json:"Subnet"`
	Gateway string `json:"Gateway"`
}

// SyncNetworks implements runtime.Runtime. An isolated network is a Docker
// "internal" network: no route to the outside.
func (d *Driver) SyncNetworks(ctx context.Context, desired []cloudagent.DesiredNetwork, remove []string) error {
	existing, err := d.ListNetworks(ctx)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, n := range existing {
		have[n] = true
	}
	var errs []error
	for _, n := range desired {
		if have[n.Bridge] {
			continue
		}
		if n.Kind == cloudagent.NetworkLab {
			errs = append(errs, fmt.Errorf("network %s: containers may not use lab networks", n.Bridge))
			continue
		}
		body := networkCreate{
			Name: n.Bridge, Driver: "bridge", Internal: n.Kind == cloudagent.NetworkIsolated,
			IPAM:    ipam{Driver: "default", Config: []ipamConfig{{Subnet: n.CIDR, Gateway: n.Gateway}}},
			Options: map[string]string{"com.docker.network.bridge.name": n.Bridge},
			Labels:  map[string]string{LabelManaged: "true", LabelNetworkID: n.ID},
		}
		if err := d.do(ctx, http.MethodPost, "/networks/create", nil, body, nil); err != nil && !statusIs(err, http.StatusConflict) {
			errs = append(errs, fmt.Errorf("network %s: %w", n.Bridge, err))
		}
	}
	for _, name := range remove {
		if !have[name] {
			continue
		}
		if err := d.do(ctx, http.MethodDelete, "/networks/"+name, nil, nil, nil); err != nil && !statusIs(err, http.StatusNotFound) {
			errs = append(errs, fmt.Errorf("remove network %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
