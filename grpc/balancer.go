package grpc

import (
	"google.golang.org/grpc/naming"
)

type staticResolver struct {
	addresses []string
}

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
