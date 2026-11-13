package ids

import (
	"testing"
	"time"
)

func TestNewV7Format(t *testing.T) {
	id := NewV7()
	if !IsUUID(id) {
		t.Fatalf("NewV7() = %q, not a canonical UUID", id)
	}
	if id[14] != '7' {
		t.Errorf("version nibble = %q, want 7", id[14])
	}
	if c := id[19]; c != '8' && c != '9' && c != 'a' && c != 'b' {
		t.Errorf("variant nibble = %q, want one of 8, 9, a, b", c)
	}
}

func TestNewV7SortsByTime(t *testing.T) {
	var g generator
	earlier := g.next(time.UnixMilli(1_700_000_000_000))
	later := g.next(time.UnixMilli(1_700_000_000_001))
	if earlier >= later {
		t.Errorf("ids do not sort by timestamp: %q >= %q", earlier, later)
	}
}

func TestNewV7IsMonotonicWithinOneMillisecond(t *testing.T) {
	var g generator
	now := time.UnixMilli(1_700_000_000_000)
	prev := g.next(now)
	// More ids than the 12-bit counter holds, all at the same instant.
	for i := range 10_000 {
		id := g.next(now)
		if !IsUUID(id) || id[14] != '7' {
			t.Fatalf("id %d malformed: %q", i, id)
		}
		if id <= prev {
			t.Fatalf("id %d not increasing: %q <= %q", i, id, prev)
		}
		prev = id
	}
}

func TestNewV7StaysMonotonicWhenClockGoesBackwards(t *testing.T) {
	var g generator
	first := g.next(time.UnixMilli(1_700_000_000_500))
	second := g.next(time.UnixMilli(1_700_000_000_100))
	if second <= first {
		t.Errorf("id after clock regression not increasing: %q <= %q", second, first)
	}
}

func TestNewV7Unique(t *testing.T) {
	seen := make(map[string]struct{}, 10_000)
	prev := ""
	for range 10_000 {
		id := NewV7()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id %q", id)
		}
		if id <= prev {
			t.Fatalf("ids not increasing: %q <= %q", id, prev)
		}
		seen[id] = struct{}{}
		prev = id
	}
}

func TestIsUUID(t *testing.T) {
	cases := map[string]bool{
		"0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1f":  true,
		"0193A7C2-5B1E-7C3A-9F10-2A4B6C8D0E1F":  false,
		"0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1":   false,
		"0193a7c25b1e7c3a9f102a4b6c8d0e1f0000":  false,
		"0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1g":  false,
		"":                                      false,
		"0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1f ": false,
	}
	for in, want := range cases {
		if got := IsUUID(in); got != want {
			t.Errorf("IsUUID(%q) = %v, want %v", in, got, want)
		}
	}
}
