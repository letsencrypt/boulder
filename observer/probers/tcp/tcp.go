package tcp

import (
	"context"

	"github.com/letsencrypt/boulder/observer/obsdialer"
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
func (p TCPProbe) Probe(ctx context.Context) bool {
	c, err := obsdialer.Dialer.DialContext(ctx, "tcp", p.hostport)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
