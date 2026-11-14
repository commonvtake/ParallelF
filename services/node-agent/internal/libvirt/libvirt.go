// Package libvirt runs VM workloads with KVM through libvirt.
//
// It drives libvirt with the virsh command line (every call is an argument
// list; nothing goes through a shell), disks with qemu-img, and cloud-init
// seeds with genisoimage. Only domains named pf-<workload id> and networks
// named pfbr-* are ever touched.
package libvirt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
	"github.com/commonvtake/parallelf/services/node-agent/internal/runtime"
)

const (
	domainPrefix  = "pf-"
	networkPrefix = "pfbr-"
)

// Driver implements runtime.Runtime for VMs.
type Driver struct {
	uri     string
	dataDir string
	run     Runner
	http    *http.Client
	now     func() time.Time

	imageMu sync.Mutex
	mu      sync.Mutex
	cpu     map[string]cpuSample
}

type cpuSample struct {
	at      time.Time
	cpuTime uint64
}

// New returns a driver for the libvirt connection uri (e.g. qemu:///system)
// that keeps images and instance files under dataDir.
func New(uri, dataDir string, run Runner) *Driver {
	return &Driver{
		uri: uri, dataDir: dataDir, run: run,
		http: &http.Client{Transport: http.DefaultTransport},
		now:  time.Now, cpu: map[string]cpuSample{},
	}
}

func (d *Driver) virsh(ctx context.Context, args ...string) ([]byte, error) {
	return d.run.Run(ctx, "virsh", append([]string{"-c", d.uri}, args...)...)
}

// Kind implements runtime.Runtime.
func (d *Driver) Kind() string { return cloudagent.KindVM }

// Probe checks /dev/kvm, libvirt and the helper programs.
func (d *Driver) Probe(ctx context.Context) (string, error) {
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		return "", fmt.Errorf("%w: /dev/kvm is not usable: %v", runtime.ErrUnavailable, err)
	} else {
		_ = f.Close()
	}
	out, err := d.virsh(ctx, "version")
	if err != nil {
		return "", fmt.Errorf("%w: %v", runtime.ErrUnavailable, err)
	}
	for _, tool := range []string{"qemu-img", "genisoimage"} {
		if _, err := d.run.Run(ctx, tool, "--version"); err != nil {
			return "", fmt.Errorf("%w: %s is not installed", runtime.ErrUnavailable, tool)
		}
	}
	return parseVersion(string(out)), nil
}

// parseVersion turns `virsh version` output into "libvirt 12.0.0, QEMU 10.2.1".
func parseVersion(out string) string {
	var libvirt, qemu string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		last := fields[len(fields)-1]
		switch {
		case strings.HasPrefix(line, "Using library: libvirt"):
			libvirt = last
		case strings.HasPrefix(line, "Running hypervisor: QEMU"):
			qemu = last
		}
	}
	parts := []string{}
	if libvirt != "" {
		parts = append(parts, "libvirt "+libvirt)
	}
	if qemu != "" {
		parts = append(parts, "QEMU "+qemu)
	}
	return strings.Join(parts, ", ")
}

func names(out []byte, prefix string) []string {
	var res []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			res = append(res, line)
		}
	}
	return res
}

// List implements runtime.Runtime.
func (d *Driver) List(ctx context.Context) (map[string]runtime.Instance, error) {
	all, err := d.virsh(ctx, "list", "--all", "--name")
	if err != nil {
		return nil, err
	}
	active, err := d.virsh(ctx, "list", "--name")
	if err != nil {
		return nil, err
	}
	running := map[string]bool{}
	for _, n := range names(active, domainPrefix) {
		running[n] = true
	}
	out := map[string]runtime.Instance{}
	for _, n := range names(all, domainPrefix) {
		id := strings.TrimPrefix(n, domainPrefix)
		out[id] = runtime.Instance{ID: id, Running: running[n]}
	}
	return out, nil
}

func (d *Driver) instanceDir(id string) (string, error) {
	clean, err := cleanName(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(d.dataDir, "instances", clean), nil
}

// Create implements runtime.Runtime: base image, overlay disk, seed ISO and
// domain definition. Each step is skipped when its result already exists,
// so an interrupted creation resumes where it stopped.
func (d *Driver) Create(ctx context.Context, w cloudagent.DesiredWorkload, network cloudagent.DesiredNetwork, progress runtime.Progress) (err error) {
	if w.CloudInit == nil {
		return errors.New("VM workload has no cloud-init seed")
	}
	dir, err := d.instanceDir(w.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Until the domain is defined, the instance directory belongs to no
	// domain; a failed attempt removes it so nothing is left behind (a
	// retry recreates it, reusing the cached base image).
	defined := false
	defer func() {
		if err != nil && !defined {
			_ = os.RemoveAll(dir)
		}
	}()

	progress("downloading image")
	base, info, err := d.ensureImage(ctx, w.Image, progress)
	if err != nil {
		return err
	}

	disk := filepath.Join(dir, "disk.qcow2")
	if _, err := os.Stat(disk); errors.Is(err, os.ErrNotExist) {
		progress("creating disk")
		tmp := disk + ".partial"
		_ = os.Remove(tmp)
		if _, err := d.run.Run(ctx, "qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base, tmp,
			sizeArg(w.DiskGiB, info.VirtualSize)); err != nil {
			return err
		}
		if err := os.Rename(tmp, disk); err != nil {
			return err
		}
	}

	progress("writing cloud-init seed")
	seed := filepath.Join(dir, "seed.iso")
	if err := d.writeSeed(ctx, dir, seed, *w.CloudInit); err != nil {
		return err
	}

	doc, err := domainDocument(w, network.Bridge, disk, seed, filepath.Join(dir, "console.log"))
	if err != nil {
		return err
	}
	defPath := filepath.Join(dir, "domain.xml")
	if err := os.WriteFile(defPath, doc, 0o644); err != nil {
		return err
	}
	progress("defining domain")
	if _, err := d.virsh(ctx, "define", defPath); err != nil {
		return err
	}
	defined = true
	return nil
}

// writeSeed builds the NoCloud ISO (volume label "cidata").
func (d *Driver) writeSeed(ctx context.Context, dir, seed string, ci cloudagent.CloudInit) error {
	src := filepath.Join(dir, "seed")
	if err := os.RemoveAll(src); err != nil {
		return err
	}
	if err := os.MkdirAll(src, 0o755); err != nil {
		return err
	}
	files := []string{"user-data", "meta-data"}
	contents := map[string]string{"user-data": ci.UserData, "meta-data": ci.MetaData}
	if ci.NetworkConfig != "" {
		files = append(files, "network-config")
		contents["network-config"] = ci.NetworkConfig
	}
	args := []string{"-quiet", "-output", seed + ".partial", "-volid", "cidata", "-joliet", "-rock"}
	for _, name := range files {
		p := filepath.Join(src, name)
		if err := os.WriteFile(p, []byte(contents[name]), 0o644); err != nil {
			return err
		}
		args = append(args, p)
	}
	if _, err := d.run.Run(ctx, "genisoimage", args...); err != nil {
		return err
	}
	return os.Rename(seed+".partial", seed)
}

// Start implements runtime.Runtime.
func (d *Driver) Start(ctx context.Context, id string) error {
	_, err := d.virsh(ctx, "start", DomainName(id))
	if err != nil && strings.Contains(err.Error(), "already active") {
		return nil
	}
	return err
}

// Stop requests an ACPI shutdown.
func (d *Driver) Stop(ctx context.Context, id string) error {
	_, err := d.virsh(ctx, "shutdown", DomainName(id))
	if err != nil && strings.Contains(err.Error(), "not running") {
		return nil
	}
	return err
}

// Kill powers the VM off.
func (d *Driver) Kill(ctx context.Context, id string) error {
	_, err := d.virsh(ctx, "destroy", DomainName(id))
	if err != nil && strings.Contains(err.Error(), "not running") {
		return nil
	}
	return err
}

// Delete removes the definition and every file of the instance.
func (d *Driver) Delete(ctx context.Context, id string) error {
	instances, err := d.List(ctx)
	if err != nil {
		return err
	}
	if inst, ok := instances[id]; ok {
		if inst.Running {
			if err := d.Kill(ctx, id); err != nil {
				return err
			}
		}
		if _, err := d.virsh(ctx, "undefine", DomainName(id)); err != nil {
			return err
		}
	}
	dir, err := d.instanceDir(id)
	if err != nil {
		return err
	}
	d.mu.Lock()
	delete(d.cpu, id)
	d.mu.Unlock()
	return os.RemoveAll(dir)
}

// Usage samples CPU time and guest memory from virsh domstats.
func (d *Driver) Usage(ctx context.Context, id string, vcpus int) (runtime.Usage, bool) {
	out, err := d.virsh(ctx, "domstats", "--raw", "--cpu-total", "--balloon", DomainName(id))
	if err != nil {
		return runtime.Usage{}, false
	}
	stats := parseStats(string(out))
	cpuTime, ok := stats["cpu.time"]
	if !ok {
		return runtime.Usage{}, false
	}
	now := d.now()

	var u runtime.Usage
	switch avail, unused := stats["balloon.available"], stats["balloon.unused"]; {
	case avail > 0 && unused > 0 && avail >= unused:
		u.MemoryUsedMiB = int64((avail - unused) / 1024)
	default:
		u.MemoryUsedMiB = int64(stats["balloon.rss"] / 1024)
	}

	d.mu.Lock()
	prev, had := d.cpu[id]
	d.cpu[id] = cpuSample{at: now, cpuTime: cpuTime}
	d.mu.Unlock()
	if !had || cpuTime < prev.cpuTime || vcpus < 1 {
		return runtime.Usage{}, false
	}
	wall := now.Sub(prev.at)
	if wall <= 0 {
		return runtime.Usage{}, false
	}
	u.CPUPercent = float64(cpuTime-prev.cpuTime) / float64(wall.Nanoseconds()) / float64(vcpus) * 100
	if u.CPUPercent > 100 {
		u.CPUPercent = 100
	}
	return u, true
}

func parseStats(out string) map[string]uint64 {
	stats := map[string]uint64{}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		if n, err := strconv.ParseUint(value, 10, 64); err == nil {
			stats[key] = n
		}
	}
	return stats
}

// ListNetworks implements runtime.Runtime.
func (d *Driver) ListNetworks(ctx context.Context) ([]string, error) {
	out, err := d.virsh(ctx, "net-list", "--all", "--name")
	if err != nil {
		return nil, err
	}
	return names(out, networkPrefix), nil
}

// SyncNetworks defines, starts and updates the desired networks and
// removes the ones in remove.
func (d *Driver) SyncNetworks(ctx context.Context, desired []cloudagent.DesiredNetwork, remove []string) error {
	all, err := d.virsh(ctx, "net-list", "--all", "--name")
	if err != nil {
		return err
	}
	active, err := d.virsh(ctx, "net-list", "--name")
	if err != nil {
		return err
	}
	defined, running := map[string]bool{}, map[string]bool{}
	for _, n := range names(all, networkPrefix) {
		defined[n] = true
	}
	for _, n := range names(active, networkPrefix) {
		running[n] = true
	}

	var errs []error
	for _, n := range desired {
		if err := d.ensureNetwork(ctx, n, defined[n.Bridge], running[n.Bridge]); err != nil {
			errs = append(errs, fmt.Errorf("network %s: %w", n.Bridge, err))
		}
	}
	for _, name := range remove {
		if !strings.HasPrefix(name, networkPrefix) {
			continue
		}
		if running[name] {
			if _, err := d.virsh(ctx, "net-destroy", name); err != nil {
				errs = append(errs, err)
				continue
			}
		}
		if defined[name] {
			if _, err := d.virsh(ctx, "net-undefine", name); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (d *Driver) ensureNetwork(ctx context.Context, n cloudagent.DesiredNetwork, defined, running bool) error {
	if !defined {
		doc, err := networkDocument(n)
		if err != nil {
			return err
		}
		dir := filepath.Join(d.dataDir, "networks")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		path := filepath.Join(dir, n.Bridge+".xml")
		if err := os.WriteFile(path, doc, 0o644); err != nil {
			return err
		}
		if _, err := d.virsh(ctx, "net-define", path); err != nil {
			return err
		}
	}
	if !running {
		if _, err := d.virsh(ctx, "net-start", n.Bridge); err != nil {
			return err
		}
		if _, err := d.virsh(ctx, "net-autostart", n.Bridge); err != nil {
			return err
		}
	}
	if n.Kind == cloudagent.NetworkLab {
		return nil
	}
	return d.syncReservations(ctx, n)
}

// syncReservations makes the network's DHCP host entries match exactly
// the reserved addresses of its VMs on this host.
func (d *Driver) syncReservations(ctx context.Context, n cloudagent.DesiredNetwork) error {
	doc, err := d.virsh(ctx, "net-dumpxml", "--inactive", n.Bridge)
	if err != nil {
		return err
	}
	current, err := parseReservations(doc)
	if err != nil {
		return err
	}
	key := func(r cloudagent.DHCPReservation) string { return strings.ToLower(r.MAC) + "|" + r.IP + "|" + r.Name }
	want := map[string]cloudagent.DHCPReservation{}
	for _, r := range n.Reservations {
		want[key(r)] = r
	}
	have := map[string]cloudagent.DHCPReservation{}
	for _, r := range current {
		have[key(r)] = r
	}
	for k, r := range have {
		if _, ok := want[k]; !ok {
			if err := d.updateHost(ctx, n.Bridge, "delete", r); err != nil {
				return err
			}
		}
	}
	for k, r := range want {
		if _, ok := have[k]; !ok {
			if err := d.updateHost(ctx, n.Bridge, "add", r); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Driver) updateHost(ctx context.Context, network, op string, r cloudagent.DHCPReservation) error {
	entry, err := hostEntry(r)
	if err != nil {
		return err
	}
	_, err = d.virsh(ctx, "net-update", network, op, "ip-dhcp-host", entry, "--live", "--config")
	return err
}
