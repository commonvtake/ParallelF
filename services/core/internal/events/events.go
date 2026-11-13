// Package events encodes pf-core domain events using the versioned
// Protobuf contracts in api/proto/parallelf/core/v1.
package events

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	corev1 "github.com/commonvtake/parallelf/gen/go/parallelf/core/v1"
	"github.com/commonvtake/parallelf/services/core/internal/projects"
)

const (
	// Source is the CloudEvents source of every pf-core event.
	Source = "/parallelf/core/pf-core"

	SubjectProjectCreated = "pf.core.evt.project.created"
	SubjectProjectDeleted = "pf.core.evt.project.deleted"

	schemaVersion = "1"
)

// Encoder implements projects.EventEncoder.
type Encoder struct {
	newID func() string
	now   func() time.Time
}

// NewEncoder returns an Encoder. newID must return a unique event id.
func NewEncoder(newID func() string, now func() time.Time) *Encoder {
	return &Encoder{newID: newID, now: now}
}

// ProjectCreated encodes a parallelf.core.v1.ProjectCreated event.
func (e *Encoder) ProjectCreated(p projects.Project) (projects.OutboxEvent, error) {
	return e.encode(SubjectProjectCreated, "project/"+p.ID, &corev1.ProjectCreated{
		ProjectId: p.ID,
		Slug:      p.Slug,
		Name:      p.Name,
		CreatedBy: p.CreatedBy,
		CreatedAt: timestamppb.New(p.CreatedAt),
	})
}

// ProjectDeleted encodes a parallelf.core.v1.ProjectDeleted event.
func (e *Encoder) ProjectDeleted(p projects.Project, deletedBy string, deletedAt time.Time) (projects.OutboxEvent, error) {
	return e.encode(SubjectProjectDeleted, "project/"+p.ID, &corev1.ProjectDeleted{
		ProjectId: p.ID,
		Slug:      p.Slug,
		DeletedBy: deletedBy,
		DeletedAt: timestamppb.New(deletedAt),
	})
}

func (e *Encoder) encode(subject, entity string, msg proto.Message) (projects.OutboxEvent, error) {
	payload, err := protojson.Marshal(msg)
	if err != nil {
		return projects.OutboxEvent{}, fmt.Errorf("encode %s: %w", subject, err)
	}
	id := e.newID()
	eventType := string(msg.ProtoReflect().Descriptor().FullName())
	return projects.OutboxEvent{
		ID:      id,
		Subject: subject,
		Type:    eventType,
		Payload: payload,
		Headers: map[string]string{
			"ce-specversion":     "1.0",
			"ce-id":              id,
			"ce-source":          Source,
			"ce-type":            eventType,
			"ce-time":            e.now().UTC().Format(time.RFC3339Nano),
			"ce-subject":         entity,
			"ce-pfschemaversion": schemaVersion,
			"content-type":       "application/json",
		},
	}, nil
}
