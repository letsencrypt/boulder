package g2s

import (
	"time"
)

type noStatsd struct{}

func (n noStatsd) Counter(float32, string, ...int)          {}
func (n noStatsd) Timing(float32, string, ...time.Duration) {}
func (n noStatsd) Gauge(float32, string, ...string)         {}

// Noop returns a struct that satisfies the Statter interface but silently
// ignores all Statter method invocations. It's designed to be used when normal
// g2s construction fails, eg.
//
//    s, err := g2s.Dial("udp", someEndpoint)
//    if err != nil {
//        log.Printf("not sending statistics to statsd (%s)", err)
//        s = g2s.Noop()
//    }
//
func Noop() Statter {
	return noStatsd{}
}
