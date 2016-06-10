package grpc

import (
	"google.golang.org/grpc/naming"
)

type staticResolver struct {
	addresses []string
}

// Resolve is called only once by grpc.RoundRobin.Start, it constructs and returns the
// naming.Watcher which actually provides addresses to grpc.Dial
func (sr *staticResolver) Resolve(target string) (naming.Watcher, error) {
	sw := &staticWatcher{}
	for _, a := range sr.addresses {
		sw.addresses = append(sw.addresses, &naming.Update{
			Op:   naming.Add,
			Addr: a,
		})
	}
	return sw, nil
}

type staticWatcher struct {
	addresses []*naming.Update
}

// Next is called in a loop by grpc.RoundRobin expecting updates to which addresses are
// appropriate. Since we just want to return a static list once return a list on the first
// call then block forever on the second instead of sitting in a tight loop
func (sw *staticWatcher) Next() ([]*naming.Update, error) {
	if sw.addresses != nil {
		addrs := sw.addresses
		sw.addresses = nil
		return addrs, nil
	}
	// Since staticWatcher.Next is called in a tight loop block forever
	// after returning the initial set of addresses
	forever := make(chan struct{})
	<-forever
	return nil, nil
}

func (sw *staticWatcher) Close() {}
