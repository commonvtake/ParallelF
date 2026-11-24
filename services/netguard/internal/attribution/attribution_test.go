package attribution

import "testing"

func TestDecode(t *testing.T) {
	c, ok, err := Decode(CloudNetworkCreated, []byte(`{"networkId":"n1","projectId":"p1","name":"web","kind":"nat","cidr":"10.20.1.0/24","createdBy":"alice","createdAt":"2026-11-24T10:00:00Z"}`))
	if err != nil || !ok || c.Network == nil || c.Network.Kind != "nat" || len(c.Claims) != 1 || c.Claims[0].IP != "10.20.1.1" || c.Claims[0].Kind != "network_gateway" {
		t.Fatalf("%+v %v", c, err)
	}
	c, _, _ = Decode(CloudNetworkCreated, []byte(`{"networkId":"n2","name":"lab","kind":"lab","cidr":"10.20.9.0/24","createdAt":"2026-11-24T10:00:00Z"}`))
	if len(c.Claims) != 0 {
		t.Fatal("lab networks have no host address")
	}
	c, _, _ = Decode(CloudWorkloadCreated, []byte(`{"workloadId":"w1","projectId":"p1","name":"vm1","ip":"10.20.1.5","createdAt":"2026-11-24T10:01:00Z"}`))
	if len(c.Claims) != 1 || c.Claims[0].EntityID != "w1" || c.Claims[0].ProjectID != "p1" {
		t.Fatalf("%+v", c)
	}
	c, _, _ = Decode(VPNDeviceCreated, []byte(`{"deviceId":"d1","name":"laptop","ownerSubject":"sub-1","ownerName":"alice","address":"10.255.0.2/32","createdAt":"2026-11-24T10:02:00Z"}`))
	if len(c.Claims) != 1 || c.Claims[0].IP != "10.255.0.2" || c.Claims[0].Name != "alice/laptop" || c.Claims[0].OwnerSubject != "sub-1" {
		t.Fatalf("%+v", c)
	}
	c, _, _ = Decode(VPNDeviceState, []byte(`{"deviceId":"d1","state":"ENROLLED","changedAt":"2026-11-24T10:03:00Z"}`))
	if len(c.Releases) != 0 {
		t.Fatal("enrolment keeps the claim")
	}
	c, _, _ = Decode(VPNDeviceState, []byte(`{"deviceId":"d1","state":"REVOKED","changedAt":"2026-11-24T10:04:00Z"}`))
	if len(c.Releases) != 1 || c.Releases[0].Kind != "vpn_device" {
		t.Fatalf("%+v", c)
	}
	if _, ok, err := Decode("pf.vpn.evt.policy.changed", []byte(`{}`)); ok || err != nil {
		t.Fatal("unused subjects are ignored")
	}
	if _, _, err := Decode(CloudWorkloadCreated, []byte(`not json`)); err == nil {
		t.Fatal("malformed payloads are errors")
	}
}
