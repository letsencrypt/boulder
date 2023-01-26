package noncebalancer

import (
	"errors"
	"sync"

	"github.com/letsencrypt/boulder/nonce"
	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/base"
)

// Compile-time assertion that *Picker implements the base.PickerBuilder
// interface.
var _ base.PickerBuilder = (*Picker)(nil)

// Picker is a base.Balancer used to construct a balancer.Picker capable of
// picking a backend (SubConn) based on the context of each RPC message. It
// implements the base.PickerBuilder and balancer.Picker interfaces but should
// only be used as a base.Balancer for nonce server clients. It can be invoked
// by passing `{"loadBalancingConfig":[{"nonce":{}}]}` as the default service
// config to grpc.Dial().
type Picker struct {
	sync.RWMutex
	backends map[balancer.SubConn]base.SubConnInfo
}

// Build implements the base.PickerBuilder interface. It is called by the gRPC
// runtime when the balancer is first initialized and when the set of backend
// (SubConn) addresses changes. It is responsible for initializing the Picker's
// backends map and returning a balancer.Picker.
func (p *Picker) Build(buildInfo base.PickerBuildInfo) balancer.Picker {
	p.Lock()
	defer p.Unlock()
	p.backends = buildInfo.ReadySCs
	return p
}

// Compile-time assertion that *Picker implements the balancer.Picker interface.
var _ balancer.Picker = (*Picker)(nil)

// Pick implements the balancer.Picker interface. It is called by the gRPC
// runtime for each RPC message. It is responsible for picking a backend
// (SubConn) based on the context of each RPC message.
func (p *Picker) Pick(info balancer.PickInfo) (balancer.PickResult, error) {
	p.RLock()
	defer p.RUnlock()

	var result balancer.PickResult
	if len(p.backends) == 0 {
		// The Picker must be rebuilt if there are no backends available.
		return result, balancer.ErrNoSubConnAvailable
	}

	// Get the destination prefix from the RPC context.
	destPrefix := info.Ctx.Value(nonce.PrefixKey{}).(string)
	if destPrefix == "" {
		// This should never happen.
		return result, errors.New("'prefix' value required in RPC context")
	}

	// Get the salt from the RPC context.
	salt := info.Ctx.Value(nonce.PrefixSaltKey{}).(string)
	if salt == "" {
		// This should never happen.
		return result, errors.New("'salt' value required in RPC context")
	}

	// Iterate over the backends and return the first one that matches the
	// destination prefix from the RPC context.
	for sc, scInfo := range p.backends {
		scPrefix := nonce.DerivePrefix(scInfo.Address.Addr, salt)
		if scPrefix == destPrefix {
			result.SubConn = sc
			return result, nil
		}
	}
	return result, balancer.ErrNoSubConnAvailable
}

func init() {
	balancer.Register(
		base.NewBalancerBuilder("nonce", &Picker{}, base.Config{}),
	)
}
