package auditlog

import "time"

// Actor identifies who performed an audited action.
type Actor struct {
	Type      string // user, agent or system
	ID        string
	Name      string
	RequestID string
}

// Record is one entry to append.
type Record struct {
	Actor        Actor
	Action       string
	ResourceType string
	ResourceID   string
	ProjectID    string
	Outcome      string // success (default), denied or failed
	Details      map[string]string
}

// View is a stored entry as APIs return it.
type View struct {
	Seq          int64             `json:"seq"`
	ID           string            `json:"id"`
	At           time.Time         `json:"at"`
	ActorType    string            `json:"actor_type"`
	ActorID      string            `json:"actor_id"`
	ActorName    string            `json:"actor_name"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	ProjectID    string            `json:"project_id,omitempty"`
	Outcome      string            `json:"outcome"`
	RequestID    string            `json:"request_id"`
	Details      map[string]string `json:"details"`
	PrevHash     string            `json:"prev_hash"`
	Hash         string            `json:"hash"`
}

// Filter narrows a listing; entries come newest first.
type Filter struct {
	ResourceType string
	ResourceID   string
	BeforeSeq    int64
	Limit        int
}

// Verification is the result of recomputing the chain.
type Verification struct {
	Valid           bool      `json:"valid"`
	Entries         int64     `json:"entries"`
	FirstInvalidSeq int64     `json:"first_invalid_seq,omitempty"`
	CheckedAt       time.Time `json:"checked_at"`
}
