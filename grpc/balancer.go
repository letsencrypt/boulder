package grpc

import (
	"sync"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type nameRoundRobin struct {
	names     chan []grpc.Address
	connected []grpc.Address
	i         int
	done      bool
	waitCh    chan struct{}
	mu        sync.Mutex
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

func (nrr *nameRoundRobin) Get(ctx context.Context, _ grpc.BalancerGetOptions) (grpc.Address, func(), error) {
	nrr.mu.Lock()
	if nrr.done {
		nrr.mu.Unlock()
		return grpc.Address{}, nil, grpc.ErrClientConnClosing
	}
	if len(nrr.connected) > 0 {
		addr := nrr.connected[nrr.i]
		nrr.i = (nrr.i + 1) % len(nrr.connected)
		nrr.mu.Unlock()
		return addr, nil, nil
	}
	var ch chan struct{}
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
	for _, a := range nrr.connected {
		if a == address {
			return nil
		}
	}
	nrr.connected = append(nrr.connected, address)
	if len(nrr.connected) == 1 && nrr.waitCh != nil {
		close(nrr.waitCh)
		nrr.waitCh = nil
	}
	return func(err error) {
		nrr.down(address, err)
	}
}

func (nrr *nameRoundRobin) down(address grpc.Address, err error) {
	// should do something with the error...?
	nrr.mu.Lock()
	defer nrr.mu.Unlock()
	for i, a := range nrr.connected {
		if a == address {
			copy(nrr.connected[i:], nrr.connected[i+1:])
			nrr.connected = nrr.connected[:len(nrr.connected)-1]
			return
		}
	}
}
