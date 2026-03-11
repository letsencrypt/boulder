package noncebalancerv2

import (
	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/balancer/base"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/resolver"
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

type builder struct {
	name   string
	config base.Config
}

// NewBalancerBuilder returns a nonce balancer builder configured by the
// provided config.
func NewBalancerBuilder(name string, config base.Config) balancer.Builder {
	return &builder{
		name:   name,
		config: config,
	}
}

func (bb *builder) Build(cc balancer.ClientConn, _ balancer.BuildOptions) balancer.Balancer {
	bal := &nonceBalancer{
		cc: cc,

		subConns: resolver.NewAddressMapV2[balancer.SubConn](),
		scStates: make(map[balancer.SubConn]connectivity.State),
		csEvltr:  &balancer.ConnectivityStateEvaluator{},
		config:   bb.config,
		state:    connectivity.Connecting,
	}
	// Initialize picker to a picker that always returns
	// ErrNoSubConnAvailable, because when state of a SubConn changes, we
	// may call UpdateState with this picker.
	bal.picker = base.NewErrPicker(balancer.ErrNoSubConnAvailable)
	return bal
}

func (bb *builder) Name() string {
	return bb.name
}

func init() {
	balancer.Register(NewBalancerBuilder(Name, base.Config{}))
}
