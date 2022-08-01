package grpc

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"google.golang.org/grpc/resolver"
)

// init registers the `staticBuilder` with the gRPC resolver registry.
func init() {
	resolver.Register(NewStaticBuilder())
}

// NewStaticBuilder creates a `staticBuilder` used to construct static DNS
// resolvers.
func NewStaticBuilder() resolver.Builder {
	return &staticBuilder{}
}

// staticBuilder implements the `resolver.Builder` interface.
type staticBuilder struct{}

// Build constructs a `staticResolver` which implements the `resolver.Resolver`
// interface. This method is typically called by the gRPC dialer, which passes a
// list of comma separated IPv4/6 addresses and a `resolver.ClientConn`. The
// state of the `resolver.ClientConn` is updated with the list of addresses and
// the `resolver.ClientConn` is wrapped in the returned `staticResolver`.
func (sb *staticBuilder) Build(target resolver.Target, cc resolver.ClientConn, _ resolver.BuildOptions) (resolver.Resolver, error) {
	var resolverAddrs []resolver.Address
	for _, address := range strings.Split(target.Endpoint, ",") {
		parsedAddress, err := parseResolverIPAddress(address)
		if err != nil {
			return nil, err
		}
		resolverAddrs = append(resolverAddrs, *parsedAddress)
	}
	return NewStaticResolver(cc, resolverAddrs), nil
}

// Scheme returns the scheme that `staticBuilder` will be registered for
// example: `static:///`.
func (sb *staticBuilder) Scheme() string {
	return "static"
}

// NewStaticResolver populates and returns a new `staticResolver` which
// implements the `resolver.Resolver` interface.
func NewStaticResolver(cc resolver.ClientConn, resolverAddrs []resolver.Address) resolver.Resolver {
	cc.UpdateState(resolver.State{Addresses: resolverAddrs})
	return &staticResolver{cc: cc}
}

// staticResolver is used to wrap an inner `resolver.ClientConn` and implements
// the `resolver.Resolver` interface.
type staticResolver struct {
	cc resolver.ClientConn
}

// ResolveNow is a no-op necessary for `staticResolver` to implement the
// `resolver.Resolver` interface. This resolver is constructed once by
// staticBuilder.Build and the state of the inner `resolver.ClientConn` is never
// updated.
func (sr *staticResolver) ResolveNow(_ resolver.ResolveNowOptions) {}

// Close is a no-op necessary for `staticResolver` to implement the
// `resolver.Resolver` interface.
func (sr *staticResolver) Close() {}

// parseResolverIPAddress takes an IPv4/6 address (ip:port, [ip]:port, or :port)
// and returns a properly formatted `resolver.Address` object. If address is in
// IPv6 format, where the host is enclosed in square brackets, the brackets will
// be stripped. The `Addr` and `ServerName` fields of the returned
// `resolver.Address` will both be set to host:port.
func parseResolverIPAddress(addr string) (*resolver.Address, error) {
	if addr == "" {
		return nil, errors.New("address is an empty string")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("address: %v", err)
	}
	if port == "" {
		// If the port field is empty the address ends with colon (e.g.
		// "[::1]:").
		return nil, fmt.Errorf("address %q missing port after port-separator colon", addr)
	}
	if host == "" {
		// Address only has a port (i.e ipv4-host:port, [ipv6-host]:port,
		// host-name:port). Keep consistent with net.Dial(); if the host is
		// empty, as in (e.g. :80), the local system is assumed.
		host = "127.0.0.1"
	}
	if net.ParseIP(host) == nil {
		// Host is a DNS name or an IPv6 address without brackets.
		return nil, fmt.Errorf("address %q is not an IP address", addr)
	}
	parsedAddr := host + ":" + port
	return &resolver.Address{
		Addr:       parsedAddr,
		ServerName: parsedAddr,
	}, nil
}
