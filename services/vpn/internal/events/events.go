// Package events encodes pf-vpnd domain events (parallelf.vpn.v1) for the
// outbox.
package events

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	vpnv1 "github.com/commonvtake/parallelf/gen/go/parallelf/vpn/v1"
	"github.com/commonvtake/parallelf/pkg/outbox"
	"github.com/commonvtake/parallelf/services/vpn/internal/domain"
)

// Source is the CloudEvents source of every pf-vpnd event.
const Source = "/parallelf/vpn/pf-vpnd"

// Subjects.
const (
	SubjectGatewayRegistered     = "pf.vpn.evt.gateway.registered"
	SubjectGatewayStatusChanged  = "pf.vpn.evt.gateway.status_changed"
	SubjectDeviceCreated         = "pf.vpn.evt.device.created"
	SubjectDeviceStateChanged    = "pf.vpn.evt.device.state_changed"
	SubjectDeviceActivated       = "pf.vpn.evt.device.activated"
	SubjectDeviceDeactivated     = "pf.vpn.evt.device.deactivated"
	SubjectPeerConnectionChanged = "pf.vpn.evt.peer.connection_changed"
	SubjectPolicyChanged         = "pf.vpn.evt.policy.changed"
)

// Encoder implements store.Encoder.
type Encoder struct{ enc *outbox.Encoder }

// NewEncoder returns an encoder.
func NewEncoder(newID func() string, now func() time.Time) *Encoder {
	return &Encoder{enc: outbox.NewEncoder(Source, newID, now)}
}

func ts(t time.Time) *timestamppb.Timestamp { return timestamppb.New(t) }

// GatewayRegistered implements store.Encoder.
func (e *Encoder) GatewayRegistered(g domain.Gateway) (outbox.Event, error) {
	return e.enc.Encode(SubjectGatewayRegistered, "gateway/"+g.ID, "", &vpnv1.GatewayRegistered{
		GatewayId: g.ID, Name: g.Name, PublicKey: g.PublicKey, Endpoint: g.Endpoint, RegisteredAt: ts(g.RegisteredAt),
	})
}

// GatewayStatusChanged implements store.Encoder.
func (e *Encoder) GatewayStatusChanged(g domain.Gateway, from string, at time.Time) (outbox.Event, error) {
	return e.enc.Encode(SubjectGatewayStatusChanged, "gateway/"+g.ID, "", &vpnv1.GatewayStatusChanged{
		GatewayId: g.ID, Name: g.Name, PreviousStatus: from, Status: g.Status, ChangedAt: ts(at),
	})
}

// DeviceCreated implements store.Encoder.
func (e *Encoder) DeviceCreated(d domain.Device) (outbox.Event, error) {
	return e.enc.Encode(SubjectDeviceCreated, "device/"+d.ID, "", &vpnv1.DeviceCreated{
		DeviceId: d.ID, Name: d.Name, OwnerSubject: d.OwnerSubject, OwnerName: d.OwnerName, Address: d.Address,
		PublicKey: d.PublicKey, Groups: d.Groups, CreatedAt: ts(d.CreatedAt), ExpiresAt: ts(d.ExpiresAt),
	})
}

// DeviceStateChanged implements store.Encoder.
func (e *Encoder) DeviceStateChanged(d domain.Device, from, actor string, at time.Time) (outbox.Event, error) {
	return e.enc.Encode(SubjectDeviceStateChanged, "device/"+d.ID, "", &vpnv1.DeviceStateChanged{
		DeviceId: d.ID, OwnerSubject: d.OwnerSubject, Address: d.Address, PreviousState: from, State: d.State,
		Actor: actor, ChangedAt: ts(at),
	})
}

// DeviceActivated implements store.Encoder.
func (e *Encoder) DeviceActivated(d domain.Device, actor string, at time.Time) (outbox.Event, error) {
	until := at
	if d.ActiveUntil != nil {
		until = *d.ActiveUntil
	}
	return e.enc.Encode(SubjectDeviceActivated, "device/"+d.ID, "", &vpnv1.DeviceActivated{
		DeviceId: d.ID, OwnerSubject: d.OwnerSubject, Address: d.Address, Actor: actor, Until: ts(until), ActivatedAt: ts(at),
	})
}

// DeviceDeactivated implements store.Encoder.
func (e *Encoder) DeviceDeactivated(d domain.Device, actor string, at time.Time) (outbox.Event, error) {
	return e.enc.Encode(SubjectDeviceDeactivated, "device/"+d.ID, "", &vpnv1.DeviceDeactivated{
		DeviceId: d.ID, OwnerSubject: d.OwnerSubject, Address: d.Address, Actor: actor, DeactivatedAt: ts(at),
	})
}

// PeerConnectionChanged implements store.Encoder.
func (e *Encoder) PeerConnectionChanged(d domain.Device, at time.Time) (outbox.Event, error) {
	return e.enc.Encode(SubjectPeerConnectionChanged, "device/"+d.ID, "", &vpnv1.PeerConnectionChanged{
		DeviceId: d.ID, OwnerSubject: d.OwnerSubject, Address: d.Address, Connected: d.Connected(),
		Endpoint: d.Endpoint, ChangedAt: ts(at),
	})
}

// PolicyChanged implements store.Encoder.
func (e *Encoder) PolicyChanged(p domain.Policy, change, actor string, at time.Time) (outbox.Event, error) {
	return e.enc.Encode(SubjectPolicyChanged, "policy/"+p.ID, "", &vpnv1.PolicyChanged{
		PolicyId: p.ID, Name: p.Name, Change: change, Actor: actor, ChangedAt: ts(at),
	})
}
