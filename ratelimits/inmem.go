package ratelimits

import (
	"fmt"
	"sync"
	"time"
)

// inmem is an in-memory implementation of the source interface used for
// testing.
type inmem struct {
	sync.RWMutex
	m map[string]time.Time
}

func newInmem() *inmem {
	return &inmem{m: make(map[string]time.Time)}
}

func (in *inmem) Set(prefix Prefix, id string, tat time.Time) {
	in.Lock()
	defer in.Unlock()
	in.m[bucketKey(prefix, id)] = tat
}

func (in *inmem) Get(prefix Prefix, id string) (time.Time, error) {
	key := bucketKey(prefix, id)
	in.RLock()
	defer in.RUnlock()
	tat, ok := in.m[key]
	if !ok {
		return time.Time{}, fmt.Errorf("bucket %q does not exist", key)
	}
	return tat, nil
}
