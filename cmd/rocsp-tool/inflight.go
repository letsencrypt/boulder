package notmain

import "sync"

type inflight struct {
	sync.RWMutex
	items map[int64]struct{}
}

func newInflight() *inflight {
	return &inflight{
		items: make(map[int64]struct{}),
	}
}

func (i *inflight) add(n int64) {
	i.Lock()
	defer i.Unlock()
	i.items[n] = struct{}{}
}

func (i *inflight) remove(n int64) {
	i.Lock()
	defer i.Unlock()
	delete(i.items, n)
}

func (i *inflight) len() int {
	i.RLock()
	defer i.RUnlock()
	return len(i.items)
}

// min returns the numerically smallest key inflight. If nothing is inflight,
// it returns 0. Note: this takes O(n) time in the number of keys and should
// be called rarely.
func (i *inflight) min() int64 {
	i.RLock()
	defer i.RUnlock()
	if len(i.items) == 0 {
		return 0
	}
	var min int64
	for k := range i.items {
		if min == 0 {
			min = k
		}
		if k < min {
			min = k
		}
	}
	return min
}
