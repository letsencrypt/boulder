package noncebalancer

import (
	"errors"

	"github.com/letsencrypt/boulder/nonce"
	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/base"
)

var errNoPrefix = errors.New("nonce.PrefixKey value required in RPC context")
var errNoPrefixSalt = errors.New("nonce.PrefixSaltKey value required in RPC context")
var errPrefixType = errors.New("nonce.PrefixKey value in RPC context must be a string")
var errPrefixSaltType = errors.New("nonce.PrefixSaltKey value in RPC context must be a string")

// Balancer is a base.Balancer used to construct a new Picker. It implements the
// base.PickerBuilder interface but should only be used as a base.Balancer for
// nonce server clients. It can be invoked by passing
// `{"loadBalancingConfig":[{"nonce":{}}]}` as the default service config to
// grpc.Dial().
type Balancer struct{}

// Compile-time assertion that *Picker implements the base.PickerBuilder
// interface.
var _ base.PickerBuilder = (*Balancer)(nil)

// Build implements the base.PickerBuilder interface. It is called by the gRPC
// runtime when the balancer is first initialized and when the set of backend
// (SubConn) addresses changes. It is responsible for initializing the Picker's
// backends map and returning a balancer.Picker.
func (b *Balancer) Build(buildInfo base.PickerBuildInfo) balancer.Picker {
	return &Picker{
		backends: buildInfo.ReadySCs,
	}
}

// Picker balancer.Picker capable of picking a backend (SubConn) based on the
// context of each RPC message. It implements balancer.Picker interface.
type Picker struct {
	backends        map[balancer.SubConn]base.SubConnInfo
	prefixToBackend map[string]balancer.SubConn
}

// Compile-time assertion that *Picker implements the balancer.Picker interface.
var _ balancer.Picker = (*Picker)(nil)

// Pick implements the balancer.Picker interface. It is called by the gRPC
// runtime for each RPC message. It is responsible for picking a backend
// (SubConn) based on the context of each RPC message.
func (p *Picker) Pick(info balancer.PickInfo) (balancer.PickResult, error) {
	var result balancer.PickResult
	if len(p.backends) == 0 {
		// The Picker must be rebuilt if there are no backends available.
		return result, balancer.ErrNoSubConnAvailable
	}

	// Get the salt from the RPC context.
	prefixSaltVal := info.Ctx.Value(nonce.PrefixSaltKey{})
	if prefixSaltVal == nil {
		// This should never happen.
		return result, errNoPrefixSalt
	}
	prefixSalt, ok := prefixSaltVal.(string)
	if !ok {
		// This should never happen.
		return result, errPrefixSaltType
	}

	if p.prefixToBackend == nil {
		// Iterate over the backends and build a map of the derived prefix for
		// each backend SubConn.
		prefixToBackend := make(map[string]balancer.SubConn)
		for sc, scInfo := range p.backends {
			scPrefix := nonce.DerivePrefix(scInfo.Address.Addr, prefixSalt)
			prefixToBackend[scPrefix] = sc
		}
		p.prefixToBackend = prefixToBackend
	}

	// Get the destination prefix from the RPC context.
	prefixVal := info.Ctx.Value(nonce.PrefixKey{})
	if prefixVal == nil {
		// This should never happen.
		return result, errNoPrefix
	}
	destPrefix, ok := prefixVal.(string)
	if !ok {
		// This should never happen.
		return result, errPrefixType
	}

	sc, ok := p.prefixToBackend[destPrefix]
	if !ok {
		// No backend SubConn was found for the destination prefix.
		return result, balancer.ErrNoSubConnAvailable
	}
	result.SubConn = sc

	return result, nil
}

func init() {
	balancer.Register(
		base.NewBalancerBuilder("nonce", &Balancer{}, base.Config{}),
	)
}
