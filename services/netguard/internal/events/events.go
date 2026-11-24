// Package events encodes pf-netguardd domain events (parallelf.netguard.v1)
// for the outbox.
package events

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	netguardv1 "github.com/commonvtake/parallelf/gen/go/parallelf/netguard/v1"
	"github.com/commonvtake/parallelf/pkg/outbox"
	"github.com/commonvtake/parallelf/services/netguard/internal/domain"
)

// Source is the CloudEvents source of every pf-netguardd event.
const Source = "/parallelf/netguard/pf-netguardd"

// Subjects.
const (
	SubjectSensorRegistered   = "pf.netguard.evt.sensor.registered"
	SubjectAlertRaised        = "pf.netguard.evt.alert.raised"
	SubjectAlertStatusChanged = "pf.netguard.evt.alert.status_changed"
	SubjectIncidentChanged    = "pf.netguard.evt.incident.changed"
	SubjectEvidenceAdded      = "pf.netguard.evt.evidence.added"
	SubjectScopeChanged       = "pf.netguard.evt.scope.changed"
)

// Encoder implements store.Encoder.
type Encoder struct{ enc *outbox.Encoder }

// NewEncoder returns an encoder.
func NewEncoder(newID func() string, now func() time.Time) *Encoder {
	return &Encoder{enc: outbox.NewEncoder(Source, newID, now)}
}

func ts(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }

func party(p *domain.Party) *netguardv1.Party {
	if p == nil {
		return nil
	}
	return &netguardv1.Party{Ip: p.IP, Kind: p.Kind, EntityId: p.EntityID, Name: p.Name, ProjectId: p.ProjectID, OwnerSubject: p.OwnerSubject}
}

// SensorRegistered implements store.Encoder.
func (e *Encoder) SensorRegistered(s domain.Sensor) (outbox.Event, error) {
	return e.enc.Encode(SubjectSensorRegistered, "sensor/"+s.ID, "", &netguardv1.SensorRegistered{
		SensorId: s.ID, Name: s.Name, Engine: s.Engine, RegisteredAt: ts(s.RegisteredAt),
	})
}

// AlertRaised implements store.Encoder.
func (e *Encoder) AlertRaised(a domain.Alert) (outbox.Event, error) {
	project := ""
	if a.Attribution.Source != nil {
		project = a.Attribution.Source.ProjectID
	}
	return e.enc.Encode(SubjectAlertRaised, "alert/"+a.ID, project, &netguardv1.AlertRaised{
		AlertId: a.ID, Detector: a.Detector, RuleId: a.RuleID, Severity: a.Severity, Title: a.Title,
		Source: party(a.Attribution.Source), Destination: party(a.Attribution.Destination), FirstSeenAt: ts(a.FirstSeenAt),
	})
}

// AlertStatusChanged implements store.Encoder.
func (e *Encoder) AlertStatusChanged(a domain.Alert, from, actor string, at time.Time) (outbox.Event, error) {
	return e.enc.Encode(SubjectAlertStatusChanged, "alert/"+a.ID, "", &netguardv1.AlertStatusChanged{
		AlertId: a.ID, PreviousStatus: from, Status: a.Status, Actor: actor, Reason: a.StatusReason, ChangedAt: ts(at),
	})
}

// IncidentChanged implements store.Encoder.
func (e *Encoder) IncidentChanged(i domain.Incident, from, actor string, at time.Time) (outbox.Event, error) {
	return e.enc.Encode(SubjectIncidentChanged, "incident/"+i.ID, "", &netguardv1.IncidentChanged{
		IncidentId: i.ID, Title: i.Title, Severity: i.Severity, PreviousStatus: from, Status: i.Status, Actor: actor, ChangedAt: ts(at),
	})
}

// EvidenceAdded implements store.Encoder.
func (e *Encoder) EvidenceAdded(ev domain.Evidence) (outbox.Event, error) {
	return e.enc.Encode(SubjectEvidenceAdded, "incident/"+ev.IncidentID, "", &netguardv1.EvidenceAdded{
		EvidenceId: ev.ID, IncidentId: ev.IncidentID, Kind: ev.Kind, Name: ev.Name, Sha256: ev.SHA256, Actor: ev.AddedBy, AddedAt: ts(ev.AddedAt),
	})
}

// ScopeChanged implements store.Encoder.
func (e *Encoder) ScopeChanged(s domain.Scope, change, actor string, at time.Time) (outbox.Event, error) {
	return e.enc.Encode(SubjectScopeChanged, "scope/"+s.ID, "", &netguardv1.ScopeChanged{
		ScopeId: s.ID, Name: s.Name, Cidrs: s.CIDRs, Change: change, Actor: actor, ValidUntil: ts(s.ValidUntil), ChangedAt: ts(at),
	})
}
