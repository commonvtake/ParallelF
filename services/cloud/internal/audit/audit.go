// Package audit computes the hash chain of the cloud audit trail.
//
// Each entry's hash covers the previous entry's hash and a canonical
// encoding of the entry itself, so changing, removing or reordering any
// stored entry breaks every hash after it. The database additionally
// refuses UPDATE, DELETE and TRUNCATE on the table.
package audit

import (
	"crypto/sha256"
	"encoding/json"
	"time"
)

// Genesis is the previous hash of the first entry.
var Genesis = make([]byte, sha256.Size)

// Entry is the hashed content of one audit row.
type Entry struct {
	ID           string
	At           time.Time
	ActorType    string
	ActorID      string
	ActorName    string
	Action       string
	ResourceType string
	ResourceID   string
	ProjectID    string
	Outcome      string
	RequestID    string
	// Details values are strings so the JSONB round trip is exact.
	Details map[string]string
}

// canonical is the encoding that is hashed. Field order is fixed by the
// struct, map keys are sorted by encoding/json, and the time is UTC with
// microsecond precision (what PostgreSQL stores).
type canonical struct {
	ID           string            `json:"id"`
	At           string            `json:"at"`
	ActorType    string            `json:"actor_type"`
	ActorID      string            `json:"actor_id"`
	ActorName    string            `json:"actor_name"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	ProjectID    string            `json:"project_id"`
	Outcome      string            `json:"outcome"`
	RequestID    string            `json:"request_id"`
	Details      map[string]string `json:"details"`
}

// Truncate rounds t to what PostgreSQL stores, so hashes computed before
// and after a round trip agree.
func Truncate(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

// Hash returns sha256(prev || canonical(e)).
func Hash(prev []byte, e Entry) []byte {
	details := e.Details
	if details == nil {
		details = map[string]string{}
	}
	body, err := json.Marshal(canonical{
		ID:           e.ID,
		At:           Truncate(e.At).Format("2006-01-02T15:04:05.000000Z"),
		ActorType:    e.ActorType,
		ActorID:      e.ActorID,
		ActorName:    e.ActorName,
		Action:       e.Action,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		ProjectID:    e.ProjectID,
		Outcome:      e.Outcome,
		RequestID:    e.RequestID,
		Details:      details,
	})
	if err != nil {
		// Only strings are encoded; Marshal cannot fail.
		panic("audit: encode entry: " + err.Error())
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(body)
	return h.Sum(nil)
}

// Verifier recomputes a chain entry by entry, in sequence order.
type Verifier struct {
	prev    []byte
	count   int64
	invalid int64
}

// NewVerifier starts a verification at the genesis hash.
func NewVerifier() *Verifier { return &Verifier{prev: Genesis} }

// Next checks one stored entry. seq identifies it in the result.
func (v *Verifier) Next(seq int64, e Entry, storedPrev, storedHash []byte) {
	v.count++
	want := Hash(v.prev, e)
	if v.invalid == 0 && (!equal(storedPrev, v.prev) || !equal(storedHash, want)) {
		v.invalid = seq
	}
	// Continue from the stored hash so one bad row is reported once.
	v.prev = storedHash
}

// Result returns the number of entries checked and the first invalid
// sequence number (0 when the chain is intact).
func (v *Verifier) Result() (entries, firstInvalid int64) { return v.count, v.invalid }

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
