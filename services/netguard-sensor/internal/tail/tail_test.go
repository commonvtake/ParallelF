package tail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(s)
	_ = f.Close()
}

func lines(b [][]byte) string {
	out := make([]string, len(b))
	for i, l := range b {
		out[i] = string(l)
	}
	return strings.Join(out, ",")
}

func TestOffsetsRotationAndPartialLines(t *testing.T) {
	dir := t.TempDir()
	log, state := filepath.Join(dir, "eve.json"), filepath.Join(dir, "state.json")
	tl, _ := Open(log, state, 100)
	if got, _, _ := tl.Read(10); len(got) != 0 {
		t.Fatal("a missing file has no lines")
	}

	appendTo(t, log, "a\nb\nc")
	got, _, _ := tl.Read(10)
	if lines(got) != "a,b" {
		t.Fatalf("got %q (the unterminated c must wait)", lines(got))
	}
	// Not committed: a restart re-delivers.
	tl2, _ := Open(log, state, 100)
	if got, _, _ := tl2.Read(10); lines(got) != "a,b" {
		t.Fatalf("redelivery %q", lines(got))
	}
	_ = tl2.Commit()

	appendTo(t, log, "\n"+strings.Repeat("x", 200)+"\nd\n")
	tl3, _ := Open(log, state, 100)
	got, skipped, _ := tl3.Read(10)
	if lines(got) != "c,d" || skipped != 1 {
		t.Fatalf("after commit %q skipped %d", lines(got), skipped)
	}
	_ = tl3.Commit()

	// Rotation: a new file under the same name starts from its beginning.
	_ = os.Rename(log, log+".1")
	appendTo(t, log, "e\n")
	if got, _, _ := tl3.Read(10); lines(got) != "e" {
		t.Fatalf("after rotation %q", lines(got))
	}
	_ = tl3.Commit()
	// Truncation also restarts.
	_ = os.Truncate(log, 0)
	appendTo(t, log, "f\n")
	if got, _, _ := tl3.Read(10); lines(got) != "f" {
		t.Fatalf("after truncation %q", lines(got))
	}
}
