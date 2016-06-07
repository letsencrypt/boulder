package grpc

import (
	"sync"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type nameRoundRobin struct {
	names     chan []grpc.Address
	connected map[grpc.Address]struct{}
	done      bool
	waitCh    chan struct{}
	mu        sync.Mutex

	// r         naming.Resolver
	// w         naming.Watcher
	// open      []Address // all the addresses the client should potentially connect
	// mu        sync.Mutex
	// addrCh    chan []Address // the channel to notify gRPC internals the list of addresses the client should connect to.
	// connected []Address      // all the connected addresses
	// next      int            // index of the next address to return for Get()
	// waitCh    chan struct{}  // the channel to block when there is no connected address available
	// done      bool           // The Balancer is closed.
}

// NameRoundRobin returns a Balancer that selects names round-robin
func NameRoundRobin(names []string) grpc.Balancer {
	nrr := &nameRoundRobin{}
	addrs := []grpc.Address{}
	for _, n := range names {
		addrs = append(addrs, grpc.Address{Addr: n})
	}
	nrr.names <- addrs
	return nrr
}

func (nrr *nameRoundRobin) Close() error {
	nrr.mu.Lock()
	defer nrr.mu.Unlock()
	nrr.done = true
	if nrr.waitCh != nil {
		close(nrr.waitCh)
	}
	if nrr.names != nil {
		close(nrr.names)
	}
	return nil
}

func (nrr *nameRoundRobin) Get(ctx context.Context, opts grpc.BalancerGetOptions) (grpc.Address, func(), error) {
	var ch chan struct{}
	nrr.mu.Lock()
	if nrr.done {
		nrr.mu.Unlock()
		return grpc.Address{}, nil, grpc.ErrClientConnClosing
	}
	if len(nrr.connected) > 0 {
		var addr grpc.Address
		for addr = range nrr.connected {
			break
		} // get random name from map
		nrr.mu.Unlock()
		return addr, nil, nil
	}
	if nrr.waitCh == nil {
		ch = make(chan struct{})
		nrr.waitCh = ch
	} else {
		ch = nrr.waitCh
	}
	nrr.mu.Unlock()
	for {
		select {
		case <-ctx.Done():
			return grpc.Address{}, nil, grpc.ErrClientConnClosing
		case <-ch:
			return nrr.Get(ctx, opts)
		}
	}
}

func (nrr *nameRoundRobin) Notify() <-chan []grpc.Address {
	return nrr.names
}

func (nrr *nameRoundRobin) Start(name string) error {
	return nil // don't need to do anything...
}

func (nrr *nameRoundRobin) Up(address grpc.Address) func(error) {
	nrr.mu.Lock()
	defer nrr.mu.Unlock()
	if _, present := nrr.connected[address]; present {
		return nil
	}
	nrr.connected[address] = struct{}{}
	if len(nrr.connected) == 1 {
		if nrr.waitCh != nil {
			close(nrr.waitCh)
			nrr.waitCh = nil
		}
	}
	return func(err error) {
		nrr.down(address, err)
	}
}

func (nrr *nameRoundRobin) down(address grpc.Address, err error) {
	// should do something with the error...?
	nrr.mu.Lock()
	defer nrr.mu.Unlock()
	delete(nrr.connected, address)
}
