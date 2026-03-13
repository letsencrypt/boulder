package noncebalancerv2

import (
	"errors"
	"sync"

	"github.com/letsencrypt/boulder/nonce"
	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/status"
)

// ErrNoBackendsMatchPrefix indicates that no backends were found which match
// the nonce prefix provided in the RPC context. This can happen when the
// provided nonce is stale, valid but the backend has since been removed from
// the balancer, or valid but the backend has not yet been added to the
// balancer.
//
// In any case, when the WFE receives this error it will return a badNonce error
// to the ACME client. Note that the WFE uses exact pointer comparison to
// detect that the status it receives is this exact status object, so don't
// wrap this with fmt.Errorf when returning it.
var ErrNoBackendsMatchPrefix = status.New(codes.Unavailable, "no backends match the nonce prefix")
var errMissingPrefixCtxKey = errors.New("nonce.PrefixCtxKey value required in RPC context")
var errMissingHMACKeyCtxKey = errors.New("nonce.HMACKeyCtxKey value required in RPC context")
var errInvalidPrefixCtxKeyType = errors.New("nonce.PrefixCtxKey value in RPC context must be a string")
var errInvalidHMACKeyCtxKeyType = errors.New("nonce.HMACKeyCtxKey value in RPC context must be a byte slice")

// picker implements the balancer.Picker interface. It picks a backend (SubConn)
// based on the nonce prefix contained in each request's Context.
type picker struct {
	// readyBackends contains only SubConns in the READY state.
	readyBackends map[balancer.SubConn]resolver.Address

	// notReadyBackends contains SubConns that the resolver reports but are not
	// in the READY state.
	notReadyBackends map[balancer.SubConn]resolver.Address

	prefixToReady       map[string]balancer.SubConn
	prefixToNotReady    map[string]balancer.SubConn
	prefixToBackendOnce sync.Once
}

// Pick is called by the gRPC runtime for each RPC. It routes the RPC to the
// backend matching the nonce prefix in the request context. If the backend
// exists but is not READY, it returns ErrNoSubConnAvailable to tell gRPC to
// queue the RPC until a new picker is available (see picker_wrapper.go:159).
func (p *picker) Pick(info balancer.PickInfo) (balancer.PickResult, error) {
	// Get the HMAC key from the RPC context.
	hmacKeyVal := info.Ctx.Value(nonce.HMACKeyCtxKey{})
	if hmacKeyVal == nil {
		// This should never happen.
		return balancer.PickResult{}, errMissingHMACKeyCtxKey
	}
	hmacKey, ok := hmacKeyVal.([]byte)
	if !ok {
		// This should never happen.
		return balancer.PickResult{}, errInvalidHMACKeyCtxKeyType
	}

	p.prefixToBackendOnce.Do(func() {
		// First call to Pick with a new Picker.
		p.prefixToReady = make(map[string]balancer.SubConn)
		for sc, addr := range p.readyBackends {
			p.prefixToReady[nonce.DerivePrefix(addr.Addr, hmacKey)] = sc
		}
		p.prefixToNotReady = make(map[string]balancer.SubConn)
		for sc, addr := range p.notReadyBackends {
			p.prefixToNotReady[nonce.DerivePrefix(addr.Addr, hmacKey)] = sc
		}
	})

	destPrefixVal := info.Ctx.Value(nonce.PrefixCtxKey{})
	if destPrefixVal == nil {
		// This should never happen.
		return balancer.PickResult{}, errMissingPrefixCtxKey
	}
	destPrefix, ok := destPrefixVal.(string)
	if !ok {
		// This should never happen.
		return balancer.PickResult{}, errInvalidPrefixCtxKeyType
	}

	sc, ok := p.prefixToReady[destPrefix]
	if ok {
		// The backend exists and is READY.
		return balancer.PickResult{SubConn: sc}, nil
	}

	_, ok = p.prefixToNotReady[destPrefix]
	if ok {
		// The backend exists but is not READY (e.g. reconnecting after a
		// GOAWAY). Tell gRPC to wait for a new picker, which will be provided
		// when the SubConn's state changes.
		return balancer.PickResult{}, balancer.ErrNoSubConnAvailable
	}

	// The backend doesn't exist at all: stale nonce, or backend removed from
	// balancer. Return a non-retryable error so the WFE can return return a
	// badNonce error.
	return balancer.PickResult{}, ErrNoBackendsMatchPrefix.Err()
}
