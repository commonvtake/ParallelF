package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseMeminfo(t *testing.T) {
	m, err := parseMeminfo(strings.NewReader("MemTotal:       16366640 kB\nMemFree: 1 kB\nMemAvailable:   15451064 kB\n"))
	if err != nil || m["MemTotal"] != 16366640 || m["MemAvailable"] != 15451064 {
		t.Fatalf("%v %v", m, err)
	}
	if _, err := parseMeminfo(strings.NewReader("garbage")); err == nil {
		t.Fatal("missing MemTotal must fail")
	}
}

func TestSampleComputesCPUFromTwoReadings(t *testing.T) {
	proc := t.TempDir()
	write := func(stat string) {
		_ = os.WriteFile(filepath.Join(proc, "stat"), []byte(stat), 0o644)
	}
	_ = os.WriteFile(filepath.Join(proc, "meminfo"), []byte("MemTotal: 2048000 kB\nMemAvailable: 1024000 kB\n"), 0o644)
	s := &Sampler{ProcDir: proc, DataDir: t.TempDir()}

	write("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 1 1 1\n")
	first, err := s.Sample(time.Now())
	if err != nil || first.CPUPercent != 0 {
		t.Fatalf("first sample %+v %v", first, err)
	}
	// +150 busy (user+system), +50 idle: 75 %.
	write("cpu  200 0 150 850 0 0 0 0 0 0\n")
	second, _ := s.Sample(time.Now())
	if second.CPUPercent != 75 || second.MemoryUsedMiB != 1000 || second.MemoryTotalMiB != 2000 || second.DiskTotalGiB <= 0 {
		t.Fatalf("second sample %+v", second)
	}
}
