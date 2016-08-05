package grpc

import (
	"google.golang.org/grpc/naming"
)

// staticResolver implements both the naming.Resolver and naming.Watcher
// interfaces. It always returns a single static list then blocks forever
type staticResolver struct {
	addresses []*naming.Update
}

func newStaticResolver(addresses []string) *staticResolver {
	sr := &staticResolver{}
	for _, a := range addresses {
		sr.addresses = append(sr.addresses, &naming.Update{
			Op:   naming.Add,
			Addr: a,
		})
	}
	return sr
}

// Resolve just returns the staticResolver it was called from as it satisfies
// both the naming.Resolver and naming.Watcher interfaces
func (sr *staticResolver) Resolve(target string) (naming.Watcher, error) {
	return sr, nil
}

// Next is called in a loop by grpc.RoundRobin expecting updates to which addresses are
// appropriate. Since we just want to return a static list once return a list on the first
// call then block forever on the second instead of sitting in a tight loop
func (sr *staticResolver) Next() ([]*naming.Update, error) {
	if sr.addresses != nil {
		addrs := sr.addresses
		sr.addresses = nil
		return addrs, nil
	}
	// Since staticResolver.Next is called in a tight loop block forever
	// after returning the initial set of addresses
	forever := make(chan struct{})
	<-forever
	return nil, nil
}

// Close does nothing
func (sr *staticResolver) Close() {}
