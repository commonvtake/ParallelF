package wg

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/commonvtake/parallelf/pkg/vpnagent"
)

const (
	keyA = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	keyB = "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0="
	keyC = "gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA="
	psk  = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="
)

func TestParseDump(t *testing.T) {
	dump := "privkey\tpubkey\t51820\toff\n" +
		keyA + "\t(none)\t192.0.2.7:40112\t10.255.0.10/32\t1795000000\t1200\t3400\t25\n" +
		keyB + "\t" + psk + "\t(none)\t(none)\t0\t0\t0\toff\n"
	peers, err := ParseDump([]byte(dump))
	if err != nil {
		t.Fatal(err)
	}
	want := []Peer{
		{PublicKey: keyA, Endpoint: "192.0.2.7:40112", AllowedIPs: []string{"10.255.0.10/32"}, Handshake: 1795000000, Rx: 1200, Tx: 3400},
		{PublicKey: keyB, PresharedKey: psk},
	}
	if !reflect.DeepEqual(peers, want) {
		t.Fatalf("got %+v", peers)
	}
	if _, err := ParseDump([]byte("iface\n" + keyA + "\tbroken")); err == nil {
		t.Fatal("a truncated line must be an error")
	}
}

type fakeRunner struct {
	dump  string
	calls []string
	stdin map[string]string
}

func (f *fakeRunner) Run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if stdin != nil {
		f.stdin[line] = string(stdin)
	}
	if line == "wg show wg-pf0 dump" {
		return []byte(f.dump), nil
	}
	return nil, nil
}

func TestSyncPeersRemovesFirstAndKeepsKeysOffTheCommandLine(t *testing.T) {
	run := &fakeRunner{stdin: map[string]string{}, dump: "i\tp\t51820\toff\n" +
		keyA + "\t(none)\t(none)\t10.255.0.10/32\t0\t0\t0\toff\n" + // unchanged
		keyC + "\t(none)\t(none)\t10.255.0.12/32\t0\t0\t0\toff\n"} // revoked
	var flushed []string
	m := &Manager{Iface: "wg-pf0", Run: run, RemoveHook: func(_ context.Context, a []string) { flushed = a }}

	n, err := m.SyncPeers(context.Background(), []vpnagent.Peer{
		{DeviceID: "a", PublicKey: keyA, Address: "10.255.0.10"},
		{DeviceID: "b", PublicKey: keyB, Address: "10.255.0.11", PresharedKey: psk},
	})
	if err != nil || n != 2 {
		t.Fatalf("changes %d err %v", n, err)
	}
	want := []string{
		"wg show wg-pf0 dump",
		"wg set wg-pf0 peer " + keyC + " remove",
		"wg set wg-pf0 peer " + keyB + " allowed-ips 10.255.0.11/32 preshared-key /dev/stdin",
	}
	if !reflect.DeepEqual(run.calls, want) {
		t.Fatalf("calls:\n%s", strings.Join(run.calls, "\n"))
	}
	if run.stdin[want[2]] != psk {
		t.Fatal("the pre-shared key must be passed on stdin")
	}
	if !reflect.DeepEqual(flushed, []string{"10.255.0.12"}) {
		t.Fatalf("flushed %v", flushed)
	}
	for _, c := range run.calls {
		if strings.Contains(c, psk) {
			t.Fatal("a key appeared in a command line")
		}
	}

	if _, err := m.SyncPeers(context.Background(), []vpnagent.Peer{{DeviceID: "x", PublicKey: "not-a-key", Address: "10.255.0.13"}}); err == nil {
		t.Fatal("an invalid key must be refused")
	}
}

type failingRunner struct{}

func (failingRunner) Run(context.Context, []byte, string, ...string) ([]byte, error) {
	return nil, errors.New("Device not found")
}

func TestPeersOfAMissingInterface(t *testing.T) {
	m := &Manager{Iface: "wg-pf0", Run: failingRunner{}}
	peers, err := m.Peers(context.Background())
	if err != nil || peers != nil {
		t.Fatalf("got %v %v", peers, err)
	}
}

func TestValidKey(t *testing.T) {
	if !ValidKey(keyA) || ValidKey("abc") || ValidKey(strings.Repeat("A", 42)+"==") {
		t.Fatal("ValidKey")
	}
}

func TestEnsureInterfacePassesTheKeyOnStdin(t *testing.T) {
	dir := t.TempDir()
	keyPath := dir + "/private.key"
	if err := os.WriteFile(keyPath, []byte(keyA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := &fakeRunner{stdin: map[string]string{}}
	m := &Manager{Iface: "wg-pf0", KeyPath: keyPath, Run: run}
	if err := m.EnsureInterface(context.Background(), vpnagent.Interface{Address: "10.255.0.1/22", ListenPort: 51820}); err != nil {
		t.Fatal(err)
	}
	set := "wg set wg-pf0 listen-port 51820 private-key /dev/stdin"
	if run.stdin[set] != keyA {
		t.Fatalf("calls %v stdin %v", run.calls, run.stdin)
	}
	for _, c := range run.calls {
		if strings.Contains(c, keyPath) || strings.Contains(c, keyA) {
			t.Fatalf("the key or its path appeared in %q", c)
		}
	}
}
