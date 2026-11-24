// Package ship turns EVE lines into batches: it parses, drops what is not
// kept, and counts what was skipped, so the shipper loop stays small and
// testable.
package ship

import (
	"errors"

	"github.com/commonvtake/parallelf/pkg/ngsensor"
	"github.com/commonvtake/parallelf/services/netguard-sensor/internal/eve"
)

// Stats counts lines that did not become events.
type Stats struct {
	NotKept   int // record types NetGuard does not keep (stats, fileinfo, ...)
	Malformed int
}

// Batch parses lines into events.
func Batch(lines [][]byte) ([]ngsensor.Event, Stats) {
	var st Stats
	events := make([]ngsensor.Event, 0, len(lines))
	for _, l := range lines {
		ev, err := eve.Parse(l, "")
		switch {
		case err == nil:
			events = append(events, ev)
		case errors.Is(err, eve.ErrSkip):
			st.NotKept++
		default:
			st.Malformed++
		}
	}
	return events, st
}
