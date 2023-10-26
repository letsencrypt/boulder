package tcp

import (
	"net"
	"time"
)

type TCPProbe struct {
	hostport string
}

// Name returns a string that uniquely identifies the monitor.

func (p TCPProbe) Name() string {
	return p.hostport
}

// Kind returns a name that uniquely identifies the `Kind` of `Prober`.
func (p TCPProbe) Kind() string {
	return "TCP"
}

// Probe performs the configured TCP dial.
func (p TCPProbe) Probe(timeout time.Duration) (bool, time.Duration) {
	start := time.Now()
	dialer := &net.Dialer{
		Timeout:       timeout,
		FallbackDelay: -1,
	}
	_, err := dialer.Dial("tcp", p.hostport)
	return err == nil, time.Since(start)
}
