package grpc

import (
	"context"
	"net"

	"google.golang.org/grpc/naming"
)

// dnsResolver implements both the naming.Resolver and naming.Watcher
// interfaces. It's a temporary shim until we upgrade to the latest gRPC, which
// has a built-in DNS resolver. It looks up the hostname only once; it doesn't
// monitor for changes.
type dnsResolver struct {
	host string
	// ch is used to enforce the "lookup only once" behavior.
	ch chan bool
}

func newDNSResolver(host string) *dnsResolver {
	return &dnsResolver{
		host: host,
		ch:   make(chan bool, 1),
	}
}

func (dr *dnsResolver) Resolve(target string) (naming.Watcher, error) {
	return dr, nil
}

// Next is called in a loop by grpc.RoundRobin expecting updates. We provide a
// single update then block forever.
func (dr *dnsResolver) Next() ([]*naming.Update, error) {
	// Stick a value on the channel, which has capacity 1. This will succed once,
	// then each subsequent call will block forever.
	dr.ch <- true
	addrs, err := net.DefaultResolver.LookupHost(context.TODO(), dr.host)
	if err != nil {
		return nil, err
	}
	var updates []*naming.Update
	for _, ip := range addrs {
		updates = append(updates, &naming.Update{
			Op:   naming.Add,
			Addr: ip,
		})
	}
	return updates, nil
}

// Close does nothing
func (dr *dnsResolver) Close() {}
