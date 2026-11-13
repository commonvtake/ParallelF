package events

import (
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	corev1 "github.com/commonvtake/parallelf/gen/go/parallelf/core/v1"
	"github.com/commonvtake/parallelf/services/core/internal/projects"
)

var (
	fixedNow = time.Date(2026, 11, 13, 18, 21, 0, 0, time.UTC)
	project  = projects.Project{
		ID:        "0193a7c2-5b1e-7c3a-9f10-2a4b6c8d0e1f",
		Slug:      "demo-lab",
		Name:      "Demo lab",
		CreatedBy: "user-1",
		CreatedAt: fixedNow.Add(-time.Minute),
	}
)

func newEncoder() *Encoder {
	return NewEncoder(func() string { return "evt-1" }, func() time.Time { return fixedNow })
}

func TestProjectCreatedMatchesContract(t *testing.T) {
	evt, err := newEncoder().ProjectCreated(project)
	if err != nil {
		t.Fatalf("ProjectCreated: %v", err)
	}
	if evt.ID != "evt-1" || evt.Subject != "pf.core.evt.project.created" || evt.Type != "parallelf.core.v1.ProjectCreated" {
		t.Errorf("unexpected envelope: %+v", evt)
	}

	var msg corev1.ProjectCreated
	if err := protojson.Unmarshal(evt.Payload, &msg); err != nil {
		t.Fatalf("payload is not a valid ProjectCreated: %v\n%s", err, evt.Payload)
	}
	if msg.GetProjectId() != project.ID || msg.GetSlug() != "demo-lab" || msg.GetName() != "Demo lab" ||
		msg.GetCreatedBy() != "user-1" || !msg.GetCreatedAt().AsTime().Equal(project.CreatedAt) {
		t.Errorf("payload fields do not match the project: %s", evt.Payload)
	}

	wantHeaders := map[string]string{
		"ce-specversion":     "1.0",
		"ce-id":              "evt-1",
		"ce-source":          "/parallelf/core/pf-core",
		"ce-type":            "parallelf.core.v1.ProjectCreated",
		"ce-time":            "2026-11-13T18:21:00Z",
		"ce-subject":         "project/" + project.ID,
		"ce-pfschemaversion": "1",
		"content-type":       "application/json",
	}
	for key, want := range wantHeaders {
		if got := evt.Headers[key]; got != want {
			t.Errorf("header %s = %q, want %q", key, got, want)
		}
	}
	if len(evt.Headers) != len(wantHeaders) {
		t.Errorf("headers = %v, want exactly %d attributes", evt.Headers, len(wantHeaders))
	}
}

func TestProjectDeletedMatchesContract(t *testing.T) {
	evt, err := newEncoder().ProjectDeleted(project, "admin-1", fixedNow)
	if err != nil {
		t.Fatalf("ProjectDeleted: %v", err)
	}
	if evt.Subject != "pf.core.evt.project.deleted" || evt.Type != "parallelf.core.v1.ProjectDeleted" {
		t.Errorf("unexpected envelope: %+v", evt)
	}
	var msg corev1.ProjectDeleted
	if err := protojson.Unmarshal(evt.Payload, &msg); err != nil {
		t.Fatalf("payload is not a valid ProjectDeleted: %v", err)
	}
	if msg.GetProjectId() != project.ID || msg.GetSlug() != "demo-lab" || msg.GetDeletedBy() != "admin-1" ||
		!msg.GetDeletedAt().AsTime().Equal(fixedNow) {
		t.Errorf("payload fields are wrong: %s", evt.Payload)
	}
}
