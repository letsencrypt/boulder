package noncebalancer

import (
	"errors"
	"sync"

	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/endpointsharding"
	"google.golang.org/grpc/balancer/pickfirst"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"

	"github.com/letsencrypt/boulder/nonce"
)

const (
	// Name is the name used to register the nonce balancer with the gRPC
	// runtime.
	Name = "noncev2"

	// SRVResolverScheme is the scheme used to invoke an instance of the SRV
	// resolver which will use the noncebalancer to pick backends. It would be
	// ideal to export this from the SRV resolver package but that package is
	// internal.
	SRVResolverScheme = "nonce-srv-v2"
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

// prefixBasedPicker implements the balancer.Picker interface. It delegates to a child Picker
// based on the endpoint (IP address and port) that Picker represents.
// The child picker is provided by endpointsharding's Balancer implementation
// (https://pkg.go.dev/google.golang.org/grpc/balancer/endpointsharding), which
// abstracts away the creation and management of SubConns for us.
//
// We happen to know the child Picker is created by the "pickfirst" balancer, but
// since each child Picker only has a single Endpoint anyhow, it doesn't really matter.
type prefixBasedPicker struct {
	// This is the full list of (address -> Picker) pairs passed in by the nonceBalancer.
	// In particular it is not filtered based on the state of any SubConn, since a given
	// address' SubConn may be temporarily unavailable while reconnecting, and we still
	// want to attempt sending traffic to that endpoint if we receive the corresponding
	// prefix.
	addrToPicker map[string]balancer.Picker

	// A mapping from nonce prefix to the child picker for that backend. This is derived,
	// on first Pick call, from the address of each backend plus the HMAC key passed in a
	// context.Context. We don't derive it on construction because we don't have access to
	// the HMAC key at that point.
	prefixToPicker     map[string]balancer.Picker
	prefixToPickerOnce sync.Once
}

// newPicker creates a prefixBasedPicker with the given map of addresses to child pickers.
func newPicker(m map[string]balancer.Picker) *prefixBasedPicker {
	return &prefixBasedPicker{
		addrToPicker: m,
	}
}

// Pick implements the balancer.Picker interface. It is called by the gRPC
// runtime for each RPC message. It is responsible for picking a backend
// (SubConn) based on the context of each RPC message.
func (p *prefixBasedPicker) Pick(info balancer.PickInfo) (balancer.PickResult, error) {
	if len(p.addrToPicker) == 0 {
		// Should never happen.
		return balancer.PickResult{}, balancer.ErrNoSubConnAvailable
	}

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

	p.prefixToPickerOnce.Do(func() {
		// First call to Pick with a new Picker.
		prefixToPicker := make(map[string]balancer.Picker)
		for addr, picker := range p.addrToPicker {
			prefix := nonce.DerivePrefix(addr, hmacKey)
			prefixToPicker[prefix] = picker
		}
		p.prefixToPicker = prefixToPicker
	})

	// Get the destination prefix from the RPC context.
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

	childPicker, ok := p.prefixToPicker[destPrefix]
	if !ok {
		// No backend SubConn was found for the destination prefix.
		return balancer.PickResult{}, ErrNoBackendsMatchPrefix.Err()
	}
	return childPicker.Pick(info)
}

// builder builds a nonceBalancer, which internally uses `endpointsharding.NewBalancer`.
//
// The embedded `endpointsharding` balancer manages a set of child pickers that all use
// `pickfirst` on an endpoint that consists of a single IP address (because our `"nonce-srv-v2"`
// resolver returns single-IP endpoints).
type builder struct{}

func (b builder) Name() string {
	return Name
}

func (b builder) Build(cc balancer.ClientConn, bOpts balancer.BuildOptions) balancer.Balancer {
	childBalancerBuilder := balancer.Get(pickfirst.Name).Build
	nb := &nonceBalancer{
		ClientConn: cc,
	}
	nb.Balancer = endpointsharding.NewBalancer(nb, bOpts, childBalancerBuilder, endpointsharding.Options{})
	return nb
}

// nonceBalancer sends nonce redemption requests to backends based on the nonce prefix,
// which maps to a specific IP address and port pair.
type nonceBalancer struct {
	balancer.Balancer
	balancer.ClientConn
}

// UpdateState creates a `prefixBasedPicker` that is aware of the IP address and port of all
// the child pickers available, including ones that may not have an active connection.
//
// The child pickers are all `pickfirst` across a single IP address.
func (b *nonceBalancer) UpdateState(state balancer.State) {
	if state.ConnectivityState != connectivity.Ready {
		b.ClientConn.UpdateState(state)
		return
	}

	addrToPicker := make(map[string]balancer.Picker)
	for _, childState := range endpointsharding.ChildStatesFromPicker(state.Picker) {
		// We expect our Endpoints to always have single Addresses, but might as well
		// be robust to the possibility there are more.
		for _, addr := range childState.Endpoint.Addresses {
			addrToPicker[addr.Addr] = childState.State.Picker
		}
	}
	b.ClientConn.UpdateState(balancer.State{
		ConnectivityState: state.ConnectivityState,
		// Here's where we build our nonce-aware picker.
		Picker: newPicker(addrToPicker),
	})
}

func init() {
	balancer.Register(builder{})
}
