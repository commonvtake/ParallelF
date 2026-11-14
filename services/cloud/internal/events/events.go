// Package events encodes pf-cloudd domain events with the versioned
// Protobuf contracts in api/proto/parallelf/cloud/v1, in the same envelope
// as every other ParallelF service (see api/events/README.md).
package events

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cloudv1 "github.com/commonvtake/parallelf/gen/go/parallelf/cloud/v1"
	"github.com/commonvtake/parallelf/services/cloud/internal/domain"
)

// Source is the CloudEvents source of every pf-cloudd event.
const Source = "/parallelf/cloud/pf-cloudd"

// Subjects.
const (
	SubjectNodeRegistered       = "pf.cloud.evt.node.registered"
	SubjectNodeStatusChanged    = "pf.cloud.evt.node.status_changed"
	SubjectNetworkCreated       = "pf.cloud.evt.network.created"
	SubjectNetworkDeleted       = "pf.cloud.evt.network.deleted"
	SubjectWorkloadCreated      = "pf.cloud.evt.workload.created"
	SubjectWorkloadStateChanged = "pf.cloud.evt.workload.state_changed"
	SubjectWorkloadDeleted      = "pf.cloud.evt.workload.deleted"
)

const schemaVersion = "1"

// Encoder implements store.Encoder.
type Encoder struct {
	newID func() string
	now   func() time.Time
}

// NewEncoder returns an Encoder. newID must return a unique event id.
func NewEncoder(newID func() string, now func() time.Time) *Encoder {
	return &Encoder{newID: newID, now: now}
}

func (e *Encoder) NodeRegistered(n domain.Node) (domain.OutboxEvent, error) {
	return e.encode(SubjectNodeRegistered, "node/"+n.ID, "", &cloudv1.NodeRegistered{
		NodeId: n.ID, Name: n.Name, Kvm: n.KVM, Docker: n.Docker,
		CpuCount: int32(n.CPUCount), MemoryMib: n.MemoryMiB, //nolint:gosec // CPU counts fit in int32
		RegisteredAt: timestamppb.New(n.RegisteredAt),
	})
}

func (e *Encoder) NodeStatusChanged(n domain.Node, from, to string, at time.Time) (domain.OutboxEvent, error) {
	return e.encode(SubjectNodeStatusChanged, "node/"+n.ID, "", &cloudv1.NodeStatusChanged{
		NodeId: n.ID, Name: n.Name, FromStatus: from, ToStatus: to, ChangedAt: timestamppb.New(at),
	})
}

func (e *Encoder) NetworkCreated(n domain.Network) (domain.OutboxEvent, error) {
	return e.encode(SubjectNetworkCreated, "network/"+n.ID, n.ProjectID, &cloudv1.NetworkCreated{
		NetworkId: n.ID, ProjectId: n.ProjectID, Name: n.Name, Kind: n.Kind, Cidr: n.CIDR,
		CreatedBy: n.CreatedBy, CreatedAt: timestamppb.New(n.CreatedAt),
	})
}

func (e *Encoder) NetworkDeleted(n domain.Network, by string, at time.Time) (domain.OutboxEvent, error) {
	return e.encode(SubjectNetworkDeleted, "network/"+n.ID, n.ProjectID, &cloudv1.NetworkDeleted{
		NetworkId: n.ID, ProjectId: n.ProjectID, Cidr: n.CIDR, DeletedBy: by, DeletedAt: timestamppb.New(at),
	})
}

func (e *Encoder) WorkloadCreated(w domain.Workload) (domain.OutboxEvent, error) {
	return e.encode(SubjectWorkloadCreated, "workload/"+w.ID, w.ProjectID, &cloudv1.WorkloadCreated{
		WorkloadId: w.ID, ProjectId: w.ProjectID, Name: w.Name, Kind: w.Kind,
		Template: fmt.Sprintf("%s@%d", w.TemplateName, w.TemplateVersion), Flavor: w.FlavorName,
		NetworkId: w.NetworkID, Ip: w.IP, Mac: w.MAC, CreatedBy: w.CreatedBy, CreatedAt: timestamppb.New(w.CreatedAt),
	})
}

func (e *Encoder) WorkloadStateChanged(w domain.Workload, from string, at time.Time) (domain.OutboxEvent, error) {
	return e.encode(SubjectWorkloadStateChanged, "workload/"+w.ID, w.ProjectID, &cloudv1.WorkloadStateChanged{
		WorkloadId: w.ID, ProjectId: w.ProjectID, FromState: from, ToState: w.State, NodeId: w.NodeID,
		Generation: w.Generation, Message: w.StatusMessage, ChangedAt: timestamppb.New(at),
	})
}

func (e *Encoder) WorkloadDeleted(w domain.Workload, at time.Time) (domain.OutboxEvent, error) {
	return e.encode(SubjectWorkloadDeleted, "workload/"+w.ID, w.ProjectID, &cloudv1.WorkloadDeleted{
		WorkloadId: w.ID, ProjectId: w.ProjectID, Ip: w.IP, DeletedAt: timestamppb.New(at),
	})
}

func (e *Encoder) encode(subject, entity, projectID string, msg proto.Message) (domain.OutboxEvent, error) {
	payload, err := protojson.Marshal(msg)
	if err != nil {
		return domain.OutboxEvent{}, fmt.Errorf("encode %s: %w", subject, err)
	}
	id := e.newID()
	eventType := string(msg.ProtoReflect().Descriptor().FullName())
	headers := map[string]string{
		"ce-specversion":     "1.0",
		"ce-id":              id,
		"ce-source":          Source,
		"ce-type":            eventType,
		"ce-time":            e.now().UTC().Format(time.RFC3339Nano),
		"ce-subject":         entity,
		"ce-pfschemaversion": schemaVersion,
		"content-type":       "application/json",
	}
	if projectID != "" {
		headers["ce-pfproject"] = projectID
	}
	return domain.OutboxEvent{ID: id, Subject: subject, Type: eventType, Payload: payload, Headers: headers}, nil
}
