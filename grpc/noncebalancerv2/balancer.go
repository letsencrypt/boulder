package noncebalancerv2

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/base"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/resolver"
)

var logger = grpclog.Component("noncebalancerv2")

// nonceBalancer implements balancer.Balancer. It is a near-exact copy of
// grpc/balancer/base/balancer.go's baseBalancer with one difference:
// regeneratePicker passes ALL resolver-tracked SubConns to the picker, not just
// READY ones. This allows the picker to distinguish "backend is temporarily
// reconnecting" (queue the RPC via ErrNoSubConnAvailable) from "prefix is
// genuinely unknown" (fail with ErrNoBackendsMatchPrefix).
type nonceBalancer struct {
	cc balancer.ClientConn

	csEvltr *balancer.ConnectivityStateEvaluator
	state   connectivity.State

	subConns *resolver.AddressMapV2[balancer.SubConn]
	scStates map[balancer.SubConn]connectivity.State
	picker   balancer.Picker
	config   base.Config

	resolverErr error // the last error reported by the resolver; cleared on successful resolution
	connErr     error // the last connection error; cleared upon leaving TransientFailure
}

func (b *nonceBalancer) ResolverError(err error) {
	b.resolverErr = err
	if b.subConns.Len() == 0 {
		b.state = connectivity.TransientFailure
	}

	if b.state != connectivity.TransientFailure {
		// The picker will not change since the balancer does not currently
		// report an error.
		return
	}
	b.regeneratePicker()
	b.cc.UpdateState(balancer.State{
		ConnectivityState: b.state,
		Picker:            b.picker,
	})
}

func (b *nonceBalancer) UpdateClientConnState(s balancer.ClientConnState) error {
	// TODO: handle s.ResolverState.ServiceConfig?
	if logger.V(2) {
		logger.Info("noncebalancer: got new ClientConn state: ", s)
	}
	// Successful resolution; clear resolver error and ensure we return nil.
	b.resolverErr = nil
	// addrsSet is the set converted from addrs, it's used for quick lookup of an address.
	addrsSet := resolver.NewAddressMapV2[any]()
	for _, a := range s.ResolverState.Addresses {
		addrsSet.Set(a, nil)
		if _, ok := b.subConns.Get(a); !ok {
			// a is a new address (not existing in b.subConns).
			var sc balancer.SubConn
			opts := balancer.NewSubConnOptions{
				HealthCheckEnabled: b.config.HealthCheck,
				StateListener:      func(scs balancer.SubConnState) { b.updateSubConnState(sc, scs) },
			}
			sc, err := b.cc.NewSubConn([]resolver.Address{a}, opts)
			if err != nil {
				logger.Warningf("noncebalancer: failed to create new SubConn: %v", err)
				continue
			}
			b.subConns.Set(a, sc)
			b.scStates[sc] = connectivity.Idle
			b.csEvltr.RecordTransition(connectivity.Shutdown, connectivity.Idle)
			sc.Connect()
		}
	}
	for _, a := range b.subConns.Keys() {
		sc, _ := b.subConns.Get(a)
		// a was removed by resolver.
		if _, ok := addrsSet.Get(a); !ok {
			sc.Shutdown()
			b.subConns.Delete(a)
			// Keep the state of this sc in b.scStates until sc's state becomes Shutdown.
			// The entry will be deleted in updateSubConnState.
		}
	}
	// If resolver state contains no addresses, return an error so ClientConn
	// will trigger re-resolve. Also records this as a resolver error, so when
	// the overall state turns transient failure, the error message will have
	// the zero address information.
	if len(s.ResolverState.Addresses) == 0 {
		b.ResolverError(errors.New("produced zero addresses"))
		return balancer.ErrBadResolverState
	}

	b.regeneratePicker()
	b.cc.UpdateState(balancer.State{ConnectivityState: b.state, Picker: b.picker})
	return nil
}

// mergeErrors builds an error from the last connection error and the last
// resolver error.  Must only be called if b.state is TransientFailure.
func (b *nonceBalancer) mergeErrors() error {
	// connErr must always be non-nil unless there are no SubConns, in which
	// case resolverErr must be non-nil.
	if b.connErr == nil {
		return fmt.Errorf("last resolver error: %v", b.resolverErr)
	}
	if b.resolverErr == nil {
		return fmt.Errorf("last connection error: %v", b.connErr)
	}
	return fmt.Errorf("last connection error: %v; last resolver error: %v", b.connErr, b.resolverErr)
}

// regeneratePicker takes a snapshot of the balancer, and generates a picker
// from it. The picker is
//   - errPicker if the balancer is in TransientFailure,
//   - a nonce picker with all READY SubConns and all known SubConns otherwise.
//
// This is the only method that differs from baseBalancer: it builds both a
// READY set and a not-READY set from b.subConns. baseBalancer only builds the
// READY set.
func (b *nonceBalancer) regeneratePicker() {
	if b.state == connectivity.TransientFailure {
		b.picker = base.NewErrPicker(b.mergeErrors())
		return
	}
	readySCs := make(map[balancer.SubConn]resolver.Address)
	notReadySCs := make(map[balancer.SubConn]resolver.Address)

	for _, addr := range b.subConns.Keys() {
		sc, _ := b.subConns.Get(addr)
		if st, ok := b.scStates[sc]; ok && st == connectivity.Ready {
			readySCs[sc] = addr
		} else {
			notReadySCs[sc] = addr
		}
	}
	b.picker = &picker{
		readyBackends:    readySCs,
		notReadyBackends: notReadySCs,
	}
}

// UpdateSubConnState is a nop because a StateListener is always set in NewSubConn.
func (b *nonceBalancer) UpdateSubConnState(sc balancer.SubConn, state balancer.SubConnState) {
	logger.Errorf("noncebalancer: UpdateSubConnState(%v, %+v) called unexpectedly", sc, state)
}

func (b *nonceBalancer) updateSubConnState(sc balancer.SubConn, state balancer.SubConnState) {
	s := state.ConnectivityState
	if logger.V(2) {
		logger.Infof("noncebalancer: handle SubConn state change: %p, %v", sc, s)
	}
	oldS, ok := b.scStates[sc]
	if !ok {
		if logger.V(2) {
			logger.Infof("noncebalancer: got state changes for an unknown SubConn: %p, %v", sc, s)
		}
		return
	}
	if oldS == connectivity.TransientFailure &&
		(s == connectivity.Connecting || s == connectivity.Idle) {
		// Once a subconn enters TRANSIENT_FAILURE, ignore subsequent IDLE or
		// CONNECTING transitions to prevent the aggregated state from being
		// always CONNECTING when many backends exist but are all down.
		if s == connectivity.Idle {
			sc.Connect()
		}
		return
	}
	b.scStates[sc] = s
	switch s {
	case connectivity.Idle:
		sc.Connect()
	case connectivity.Shutdown:
		// When an address was removed by resolver, b called Shutdown but kept
		// the sc's state in scStates. Remove state for this sc here.
		delete(b.scStates, sc)
	case connectivity.TransientFailure:
		// Save error to be reported via picker.
		b.connErr = state.ConnectionError
	}

	b.state = b.csEvltr.RecordTransition(oldS, s)

	// Regenerate picker when one of the following happens:
	//  - this sc entered or left ready
	//  - the aggregated state of balancer is TransientFailure
	//    (may need to update error message)
	if (s == connectivity.Ready) != (oldS == connectivity.Ready) ||
		b.state == connectivity.TransientFailure {
		b.regeneratePicker()
	}
	b.cc.UpdateState(balancer.State{ConnectivityState: b.state, Picker: b.picker})
}

// Close is a nop because base balancer doesn't have internal state to clean up,
// and it doesn't need to call Shutdown for the SubConns.
func (b *nonceBalancer) Close() {
}

// ExitIdle is a nop because the base balancer attempts to stay connected to
// all SubConns at all times.
func (b *nonceBalancer) ExitIdle() {
}
