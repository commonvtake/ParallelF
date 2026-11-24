package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func hashOf(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}
