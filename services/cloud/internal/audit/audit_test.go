package audit

import (
	"bytes"
	"testing"
	"time"
)

func entry(id string) Entry {
	return Entry{
		ID: id, At: time.Date(2026, 11, 13, 18, 0, 0, 123456789, time.UTC),
		ActorType: "user", ActorID: "sub-1", ActorName: "owner",
		Action: "cloud.workloads.delete", ResourceType: "workload", ResourceID: "w-1",
		Outcome: "success", RequestID: "req-1", Details: map[string]string{"name": "web", "a": "<b>"},
	}
}

func TestHashIgnoresSubMicrosecondPrecisionAndMapOrder(t *testing.T) {
	a := entry("1")
	b := entry("1")
	b.At = b.At.Truncate(time.Microsecond).In(time.FixedZone("CST", -6*3600))
	b.Details = map[string]string{"a": "<b>", "name": "web"}

	if !bytes.Equal(Hash(Genesis, a), Hash(Genesis, b)) {
		t.Fatal("hash must depend only on stored precision and content")
	}
}

func TestHashCoversEveryField(t *testing.T) {
	base := Hash(Genesis, entry("1"))
	mutations := []func(*Entry){
		func(e *Entry) { e.ActorID = "sub-2" },
		func(e *Entry) { e.Action = "cloud.workloads.create" },
		func(e *Entry) { e.ResourceID = "w-2" },
		func(e *Entry) { e.Outcome = "denied" },
		func(e *Entry) { e.Details["name"] = "db" },
		func(e *Entry) { e.At = e.At.Add(time.Microsecond) },
	}
	for i, mutate := range mutations {
		e := entry("1")
		mutate(&e)
		if bytes.Equal(base, Hash(Genesis, e)) {
			t.Errorf("mutation %d did not change the hash", i)
		}
	}
	if bytes.Equal(base, Hash(bytes.Repeat([]byte{1}, 32), entry("1"))) {
		t.Error("previous hash must be covered")
	}
}

func chain(n int) (entries []Entry, prevs, hashes [][]byte) {
	prev := Genesis
	for i := 0; i < n; i++ {
		e := entry(string(rune('a' + i)))
		h := Hash(prev, e)
		entries, prevs, hashes = append(entries, e), append(prevs, prev), append(hashes, h)
		prev = h
	}
	return
}

func TestVerifierAcceptsAnIntactChain(t *testing.T) {
	entries, prevs, hashes := chain(5)
	v := NewVerifier()
	for i := range entries {
		v.Next(int64(i+1), entries[i], prevs[i], hashes[i])
	}
	if n, bad := v.Result(); n != 5 || bad != 0 {
		t.Fatalf("got entries=%d invalid=%d", n, bad)
	}
}

func TestVerifierFindsTheFirstAlteredEntry(t *testing.T) {
	entries, prevs, hashes := chain(5)
	entries[2].Outcome = "success-but-edited"

	v := NewVerifier()
	for i := range entries {
		v.Next(int64(i+1), entries[i], prevs[i], hashes[i])
	}
	if _, bad := v.Result(); bad != 3 {
		t.Fatalf("first invalid = %d, want 3", bad)
	}
}

func TestVerifierFindsARemovedEntry(t *testing.T) {
	entries, prevs, hashes := chain(5)
	v := NewVerifier()
	for i := range entries {
		if i == 1 {
			continue
		}
		v.Next(int64(i+1), entries[i], prevs[i], hashes[i])
	}
	if _, bad := v.Result(); bad != 3 {
		t.Fatalf("first invalid = %d, want 3", bad)
	}
}
