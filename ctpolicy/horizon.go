package ctpolicy

import (
	"slices"
	"time"

	"github.com/letsencrypt/boulder/ctpolicy/loglist"
)

// horizonNever is returned when there is no horizon.
// This is only possible when non-sharded logs alone suffice.
// In practice this won't happen.
var horizonNever = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

// satisfiable returns true if the given logs can produce a set of SCTs which
// satisfies the CT policy. It is pretending every log returned an SCT.
func satisfiable(logs loglist.List) bool {
	results := make([]result, len(logs))
	for i, log := range logs {
		results[i] = result{log: log}
	}
	return compliantSet(results) != nil
}

// horizon returns the earliest certificate expiry time, no earlier than now,
// for which the given logs cannot satisfy the CT policy.
func horizon(logs loglist.List, now time.Time) time.Time {
	candidates := []time.Time{now}
	for _, log := range logs {
		// We only have to check the points in time when a log's interval ends.
		// Since log ends are exclusive, that's the moment where the horizon will be.
		if log.EndExclusive.After(now) {
			candidates = append(candidates, log.EndExclusive)
		}
	}
	slices.SortFunc(candidates, time.Time.Compare)

	// Find the first candidate time that isn't satisfiable.
	for _, t := range candidates {
		if !satisfiable(logs.ForTime(t)) {
			return t
		}
	}

	// If all log ends are satisfiable, there's never a horizon
	return horizonNever
}
