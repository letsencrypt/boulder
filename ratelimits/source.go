package ratelimits

import (
	"fmt"
	"sync"
	"time"
)

// ErrBucketNotFound indicates that the bucket was not found.
var ErrBucketNotFound = fmt.Errorf("bucket not found")

type source interface {
	Set(name Name, id string, tat time.Time) error
	Get(name Name, id string) (time.Time, error)
	Delete(name Name, id string) error
}

// inmem is an in-memory implementation of the source interface used for
// testing.
type inmem struct {
	sync.RWMutex
	m map[string]time.Time
}

func newInmem() *inmem {
	return &inmem{m: make(map[string]time.Time)}
}

func (in *inmem) Set(name Name, id string, tat time.Time) error {
	in.Lock()
	defer in.Unlock()
	in.m[bucketKey(name, id)] = tat
	return nil
}

func (in *inmem) Get(name Name, id string) (time.Time, error) {
	key := bucketKey(name, id)
	in.RLock()
	defer in.RUnlock()
	tat, ok := in.m[key]
	if !ok {
		return time.Time{}, ErrBucketNotFound
	}
	return tat, nil
}

func (in *inmem) Delete(name Name, id string) error {
	key := bucketKey(name, id)
	in.Lock()
	defer in.Unlock()
	delete(in.m, key)
	return nil
}
