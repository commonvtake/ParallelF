// Package pskcrypt generates WireGuard pre-shared keys and encrypts them at
// rest with AES-256-GCM under a key-encryption key (KEK) from a secret.
package pskcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// Box encrypts and decrypts pre-shared keys.
type Box struct{ aead cipher.AEAD }

// New returns a Box for a base64-encoded 32-byte KEK.
func New(kekBase64 string) (*Box, error) {
	kek, err := base64.StdEncoding.DecodeString(kekBase64)
	if err != nil || len(kek) != 32 {
		return nil, errors.New("the pre-shared key KEK must be 32 bytes, base64-encoded")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Generate returns a new random pre-shared key (base64) and its ciphertext.
func (b *Box) Generate(associated string) (string, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", nil, err
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, err
	}
	sealed := b.aead.Seal(nonce, nonce, key, []byte(associated))
	return base64.StdEncoding.EncodeToString(key), sealed, nil
}

// Open decrypts a ciphertext produced by Generate with the same associated
// data (the device ID binds a key to its device).
func (b *Box) Open(ciphertext []byte, associated string) (string, error) {
	n := b.aead.NonceSize()
	if len(ciphertext) < n {
		return "", errors.New("pre-shared key ciphertext too short")
	}
	key, err := b.aead.Open(nil, ciphertext[:n], ciphertext[n:], []byte(associated))
	if err != nil {
		return "", fmt.Errorf("decrypt pre-shared key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
