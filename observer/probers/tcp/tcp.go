package tcp

import (
	"context"

	"github.com/letsencrypt/boulder/observer/obsclient"
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
func (p TCPProbe) Probe(ctx context.Context) error {
	c, err := obsclient.Dialer().DialContext(ctx, "tcp", p.hostport)
	if err != nil {
		return err
	}

	c.Close()
	return nil
}
