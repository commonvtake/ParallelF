// Package host reports the compute node's capacity and utilisation from
// /proc and the filesystem holding the agent's data.
package host

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/commonvtake/parallelf/pkg/cloudagent"
)

// Sampler reads host statistics. CPU utilisation needs two readings, so it
// remembers the previous one.
type Sampler struct {
	ProcDir string // normally /proc
	DataDir string // filesystem whose size is reported as disk

	mu       sync.Mutex
	prevBusy uint64
	prevAll  uint64
}

// NewSampler returns a Sampler for the real host.
func NewSampler(dataDir string) *Sampler { return &Sampler{ProcDir: "/proc", DataDir: dataDir} }

// Capacity returns CPUs, memory and the data filesystem's size.
func (s *Sampler) Capacity() (cpus int, memMiB, diskGiB int64, err error) {
	mem, err := s.meminfo()
	if err != nil {
		return 0, 0, 0, err
	}
	total, _, err := disk(s.DataDir)
	if err != nil {
		return 0, 0, 0, err
	}
	return runtime.NumCPU(), mem["MemTotal"] / 1024, int64(total / (1 << 30)), nil
}

// Sample takes one utilisation reading.
func (s *Sampler) Sample(now time.Time) (cloudagent.NodeMetrics, error) {
	mem, err := s.meminfo()
	if err != nil {
		return cloudagent.NodeMetrics{}, err
	}
	busy, all, err := s.cpuTimes()
	if err != nil {
		return cloudagent.NodeMetrics{}, err
	}
	total, free, err := disk(s.DataDir)
	if err != nil {
		return cloudagent.NodeMetrics{}, err
	}

	s.mu.Lock()
	var cpu float64
	if s.prevAll > 0 && all > s.prevAll && busy >= s.prevBusy {
		cpu = float64(busy-s.prevBusy) / float64(all-s.prevAll) * 100
	}
	s.prevBusy, s.prevAll = busy, all
	s.mu.Unlock()

	used := mem["MemTotal"] - mem["MemAvailable"]
	return cloudagent.NodeMetrics{
		At: now.UTC(), CPUPercent: cpu,
		MemoryUsedMiB: used / 1024, MemoryTotalMiB: mem["MemTotal"] / 1024,
		DiskUsedGiB: float64(total-free) / (1 << 30), DiskTotalGiB: float64(total) / (1 << 30),
	}, nil
}

// meminfo returns /proc/meminfo values in KiB.
func (s *Sampler) meminfo() (map[string]int64, error) {
	f, err := os.Open(s.ProcDir + "/meminfo")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return parseMeminfo(f)
}

func parseMeminfo(r io.Reader) (map[string]int64, error) {
	out := map[string]int64{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		if v, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
			out[key] = v
		}
	}
	if out["MemTotal"] == 0 {
		return nil, fmt.Errorf("meminfo: no MemTotal")
	}
	return out, sc.Err()
}

// cpuTimes returns busy and total jiffies from the aggregate "cpu" line.
func (s *Sampler) cpuTimes() (busy, all uint64, err error) {
	f, err := os.Open(s.ProcDir + "/stat")
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = f.Close() }()
	return parseStat(f)
}

func parseStat(r io.Reader) (busy, all uint64, err error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		for i, f := range fields[1:] {
			v, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("stat: %w", err)
			}
			all += v
			// idle (3) and iowait (4) are not busy time.
			if i != 3 && i != 4 {
				busy += v
			}
		}
		return busy, all, nil
	}
	return 0, 0, fmt.Errorf("stat: no cpu line")
}

func disk(path string) (total, free uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	bsize := uint64(st.Bsize) //nolint:gosec // block size is positive
	return st.Blocks * bsize, st.Bavail * bsize, nil
}
