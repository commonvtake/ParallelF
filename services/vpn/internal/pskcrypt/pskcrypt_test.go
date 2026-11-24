package pskcrypt

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestRoundTripAndBinding(t *testing.T) {
	kek := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	box, err := New(kek)
	if err != nil {
		t.Fatal(err)
	}
	psk, sealed, err := box.Generate("device-a")
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := base64.StdEncoding.DecodeString(psk); len(raw) != 32 || bytes.Contains(sealed, raw) {
		t.Fatal("the key must be 32 bytes and not stored in the clear")
	}
	if got, err := box.Open(sealed, "device-a"); err != nil || got != psk {
		t.Fatalf("open %v", err)
	}
	if _, err := box.Open(sealed, "device-b"); err == nil {
		t.Fatal("a ciphertext must not open for another device")
	}
	other, _ := New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	if _, err := other.Open(sealed, "device-a"); err == nil {
		t.Fatal("a ciphertext must not open under another KEK")
	}
	if _, err := New("c2hvcnQ="); err == nil {
		t.Fatal("a short KEK must be refused")
	}
}
