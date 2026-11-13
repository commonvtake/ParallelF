// Package ids generates identifiers used across ParallelF services.
package ids

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// generator produces UUIDv7 values that are strictly increasing within one
// process, using the 12-bit rand_a field as a counter (RFC 9562, method 1).
type generator struct {
	mu      sync.Mutex
	lastMS  uint64
	counter uint16
}

var defaultGenerator generator

// NewV7 returns a UUID version 7 (RFC 9562): a 48-bit Unix millisecond
// timestamp, a 12-bit counter and 62 random bits. Values sort by creation
// time, which keeps B-tree primary-key inserts local and makes the id usable
// as a pagination cursor. Within a process, ids are strictly increasing even
// when several are generated in the same millisecond.
func NewV7() string {
	return defaultGenerator.next(time.Now())
}

func (g *generator) next(now time.Time) string {
	var random [10]byte
	if _, err := rand.Read(random[:]); err != nil {
		// crypto/rand never fails on supported platforms; a failure means
		// the process cannot generate identifiers safely.
		panic(fmt.Sprintf("ids: crypto/rand failed: %v", err))
	}

	ms := uint64(now.UnixMilli()) // time after 1970 is non-negative

	g.mu.Lock()
	switch {
	case ms > g.lastMS:
		g.lastMS = ms
		// Start in the lower half of the counter space so a burst within
		// one millisecond has room to grow.
		g.counter = (uint16(random[0])<<8 | uint16(random[1])) & 0x07ff
	case g.counter < 0x0fff:
		g.counter++
	default:
		// Counter exhausted (or the clock went backwards far enough to
		// catch up): borrow the next millisecond to stay monotonic.
		g.lastMS++
		g.counter = 0
	}
	ms, counter := g.lastMS, g.counter
	g.mu.Unlock()

	var b [16]byte
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	b[6] = 0x70 | byte(counter>>8) // version 7 + counter high bits
	b[7] = byte(counter)
	copy(b[8:], random[2:])
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 9562 variant

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:])
}

// IsUUID reports whether s is a canonical lower-case UUID string.
func IsUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}
