package ctconfig

import (
	"errors"
	"fmt"
	"time"

	"github.com/letsencrypt/boulder/cmd"
)

// LogShard describes a single shard of a temporally sharded
// CT log
type LogShard struct {
	URI         string
	Key         string
	WindowStart time.Time
	WindowEnd   time.Time
}

// TemporalSet contains a set of temporal shards of a single log
type TemporalSet struct {
	Name   string
	Shards []LogShard
}

// Setup initializes the TemporalSet by parsing the start and end dates
// and verifying WindowEnd > WindowStart
func (ts *TemporalSet) Setup() error {
	if ts.Name == "" {
		return errors.New("Name cannot be empty")
	}
	if len(ts.Shards) == 0 {
		return errors.New("temporal set contains no shards")
	}
	for i := range ts.Shards {
		if ts.Shards[i].WindowEnd.Before(ts.Shards[i].WindowStart) ||
			ts.Shards[i].WindowEnd.Equal(ts.Shards[i].WindowStart) {
			return errors.New("WindowStart must be before WindowEnd")
		}
	}
	return nil
}

// pick chooses the correct shard from a TemporalSet to use for the given
// expiration time. In the case where two shards have overlapping windows
// the earlier of the two shards will be chosen.
func (ts *TemporalSet) pick(exp time.Time) (*LogShard, error) {
	for _, shard := range ts.Shards {
		if exp.Before(shard.WindowStart) {
			continue
		}
		if !exp.Before(shard.WindowEnd) {
			continue
		}
		return &shard, nil
	}
	return nil, fmt.Errorf("no valid shard available for temporal set %q for expiration date %q", ts.Name, exp)
}

// LogDescription contains the information needed to submit certificates
// to a CT log and verify returned receipts. If TemporalSet is non-nil then
// URI and Key should be empty.
type LogDescription struct {
	URI             string
	Key             string
	SubmitFinalCert bool

	*TemporalSet
}

// Info returns the URI and key of the log, either from a plain log description
// or from the earliest valid shard from a temporal log set
func (ld LogDescription) Info(exp time.Time) (string, string, error) {
	if ld.TemporalSet == nil {
		return ld.URI, ld.Key, nil
	}
	shard, err := ld.TemporalSet.pick(exp)
	if err != nil {
		return "", "", err
	}
	return shard.URI, shard.Key, nil
}

type CTGroup struct {
	Name string
	Logs []LogDescription
	// How long to wait for one log to accept a certificate before moving on to
	// the next.
	Stagger cmd.ConfigDuration
}
