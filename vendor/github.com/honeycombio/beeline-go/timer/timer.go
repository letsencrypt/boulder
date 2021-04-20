// Package timer is a small convenience package for timing blocks of code.
package timer

import "time"

// Timer is the thing that you pass around to time blocks of code. Represented
// as an interface so that other implementations can do fancy things with the
// values in addition to just returning them, such as submit them to
// instrumentation frameworks.
type Timer interface {
	// Finish calculates the time since the timer was started and returns its
	// representation in milliseconds
	Finish() float64
}

// timer gives you an object to pass around for timing your code
type timer struct {
	start time.Time
}

// New creates a new timer with an arbitrary starting time
func New(t time.Time) Timer {
	return &timer{
		start: t,
	}
}

// Start creates a new timer using `time.Now()` as the starting time
func Start() Timer {
	return &timer{
		start: time.Now(),
	}
}

// Finish closes off a started timer. It returns the duration timed in
// milliseconds. Will return zero for timers that were never started.
func (t timer) Finish() float64 {
	if t.start.IsZero() {
		return 0
	}
	return float64(time.Since(t.start)) / float64(time.Millisecond)
}
