package events

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
)

func TestWorkloadStateChangedEnvelopeAndPayload(t *testing.T) {
	at := time.Date(2026, 11, 13, 18, 0, 0, 0, time.UTC)
	enc := NewEncoder(func() string { return "evt-1" }, func() time.Time { return at })

	evt, err := enc.WorkloadStateChanged(domain.Workload{
		ID: "w-1", ProjectID: "p-1", NodeID: "n-1", State: domain.StateRunning, Generation: 3,
	}, domain.StateProvisioning, at)
	if err != nil {
		t.Fatal(err)
	}

	if evt.Subject != SubjectWorkloadStateChanged || evt.Type != "parallelf.cloud.v1.WorkloadStateChanged" {
		t.Fatalf("subject/type: %s %s", evt.Subject, evt.Type)
	}
	want := map[string]string{
		"ce-specversion": "1.0", "ce-id": "evt-1", "ce-source": Source, "ce-type": evt.Type,
		"ce-subject": "workload/w-1", "ce-pfproject": "p-1", "ce-pfschemaversion": "1", "content-type": "application/json",
	}
	for k, v := range want {
		if evt.Headers[k] != v {
			t.Errorf("header %s = %q, want %q", k, evt.Headers[k], v)
		}
	}
	var payload map[string]any
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["fromState"] != "PROVISIONING" || payload["toState"] != "RUNNING" || payload["generation"] != "3" {
		t.Fatalf("payload: %v", payload)
	}
}

func TestNodeEventsHaveNoProject(t *testing.T) {
	enc := NewEncoder(func() string { return "evt-2" }, time.Now)
	evt, err := enc.NodeRegistered(domain.Node{ID: "n-1", Name: "host-1", KVM: true, CPUCount: 4, MemoryMiB: 16000})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := evt.Headers["ce-pfproject"]; ok {
		t.Fatal("node events are not project-scoped")
	}
}
