// Package clock provides an abstraction for system time that enables
// testing of time-sensitive code.
//
// By passing in Default to production code, you can then use NewFake
// in tests to create Clocks that control what time the production
// code sees.
//
// Be sure to test Time equality with time.Time#Equal, not ==.
package clock

import (
	"sync"
	"time"
)

var systemClock Clock = sysClock{}

// Default returns a Clock that matches the actual system time.
func Default() Clock {
	// This is a method instead of a public var to prevent folks from
	// "making things work" by writing to the var instead of passing
	// in a Clock.
	return systemClock
}

// Clock is an abstraction over system time. New instances of it can
// be made with Default and NewFake.
type Clock interface {
	// Now returns the Clock's current view of the time. Mutating the
	// returned Time will not mutate the clock's time.
	Now() time.Time
}

type sysClock struct{}

func (s sysClock) Now() time.Time {
	return time.Now()
}

// NewFake returns a FakeClock to be used in tests that need to
// manipulate time. Its initial value is always the unix epoch in the
// UTC timezone. The FakeClock returned is thread-safe.
func NewFake() FakeClock {
	// We're explicit about this time construction to avoid early user
	// questions about why the time object doesn't have a Location by
	// default.
	return &fake{t: time.Unix(0, 0).UTC()}
}

// FakeClock is a Clock with additional controls. The return value of
// Now return can be modified with Add. Use NewFake to get a
// thread-safe FakeClock implementation.
type FakeClock interface {
	Clock
	// Adjust the time that will be returned by Now.
	Add(d time.Duration)
}

// To prevent mistakes with the API, we hide this behind NewFake. It's
// easy forget to create a pointer to a fake since time.Time (and
// sync.Mutex) are also simple values. The code will appear to work
// but the clock's time will never be adjusted.
type fake struct {
	sync.RWMutex
	t time.Time
}

func (f *fake) Now() time.Time {
	f.RLock()
	defer f.RUnlock()
	return f.t
}

func (f *fake) Add(d time.Duration) {
	f.Lock()
	defer f.Unlock()
	f.t = f.t.Add(d)
}
