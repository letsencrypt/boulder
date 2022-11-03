package grpc

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/honeycombio/beeline-go/wrappers/hnygrpc"
	"github.com/jmhodges/clock"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/letsencrypt/boulder/cmd"
)

// CodedError is a alias required to appease go vet
var CodedError = status.Errorf

var errNilTLS = errors.New("boulder/grpc: received nil tls.Config")

type service struct {
	cfg  cmd.GRPCServiceConfig
	desc *grpc.ServiceDesc
	impl any
}

// serverBuilder
type serverBuilder struct {
	cfg      *cmd.GRPCServerConfig
	services map[string]service
	err      error
}

// NewServer returns an object which can be used to build gRPC servers. It
// takes the server's configuration to perform initialization, and automatically
// adds the first service, the default gRPC health service.
func NewServer(c *cmd.GRPCServerConfig) *serverBuilder {
	s := make(map[string]service)
	if len(c.Services) > 0 {
		for serviceName, serviceCfg := range c.Services {
			s[serviceName] = service{cfg: serviceCfg}
		}
	}

	ret := &serverBuilder{cfg: c, services: s}
	ret = ret.Add(&healthpb.Health_ServiceDesc, health.NewServer())
	return ret
}

// Add registers a new service (consisting of its description and its
// implementation) to the set of services which will be exposed by this server.
// It returns the modified-in-place serverBuilder so that calls can be chained.
// If there is an error adding this service, it will be exposed when .Build() is
// called.
func (sb *serverBuilder) Add(desc *grpc.ServiceDesc, impl any) *serverBuilder {
	s, ok := sb.services[desc.ServiceName]
	if !ok {
		// If this service doesn't have its own config stanza, instead initialize it
		// with pieces from the server-level config.
		s = service{cfg: cmd.GRPCServiceConfig{ClientNames: sb.cfg.ClientNames}}
	}

	if s.desc != nil || s.impl != nil {
		// We've already registered a service with this same name, error out.
		sb.err = fmt.Errorf("attempted double-registration of gRPC service %q", desc.ServiceName)
		return sb
	}

	s.desc = desc
	s.impl = impl
	sb.services[desc.ServiceName] = s

	return sb
}

// Build creates a gRPC server that uses the provided *tls.Config and exposes
// all of the services added to the builder. It also exposes a health check
// service. It returns two functions, start() and stop(), which should be used
// to start and gracefully stop the server.
func (sb *serverBuilder) Build(tlsConfig *tls.Config, statsRegistry prometheus.Registerer, clk clock.Clock, interceptors ...grpc.UnaryServerInterceptor) (func() error, func(), error) {
	if sb.err != nil {
		return nil, nil, sb.err
	}

	// TODO: Remove this check once all Boulder components have their services
	// properly configured. In theory we'd like to keep this, but we can't do both
	// this and the desired check in .Add() for deployability reasons.
	for serviceName := range sb.cfg.Services {
		_, ok := sb.services[serviceName]
		if !ok {
			return nil, nil, fmt.Errorf("gRPC service %q configured but not registered", serviceName)
		}
	}

	if tlsConfig == nil {
		return nil, nil, errNilTLS
	}

	acceptedSANs := make(map[string]struct{})
	for _, name := range sb.cfg.ClientNames {
		acceptedSANs[name] = struct{}{}
	}
	for _, service := range sb.services {
		for _, name := range service.cfg.ClientNames {
			acceptedSANs[name] = struct{}{}
		}
	}

	metrics, err := newServerMetrics(statsRegistry)
	if err != nil {
		return nil, nil, err
	}

	creds, err := bcreds.NewServerCredentials(tlsConfig, acceptedSANs)
	if err != nil {
		return nil, nil, err
	}

	listener, err := net.Listen("tcp", sb.cfg.Address)
	if err != nil {
		return nil, nil, err
	}

	var ai serverInterceptor
	if len(sb.cfg.Services) > 0 {
		ai = newServiceAuthChecker(sb.cfg)
	} else {
		ai = &noopServerInterceptor{}
	}

	mi := newServerMetadataInterceptor(metrics, clk)

	unaryInterceptors := append([]grpc.UnaryServerInterceptor{
		mi.metrics.grpcMetrics.UnaryServerInterceptor(),
		ai.Unary,
		mi.Unary,
		hnygrpc.UnaryServerInterceptor(),
	}, interceptors...)

	streamInterceptors := []grpc.StreamServerInterceptor{
		mi.metrics.grpcMetrics.StreamServerInterceptor(),
		ai.Stream,
		mi.Stream,
		// TODO(#6361): Get a tracing interceptor that works for gRPC streams.
	}

	options := []grpc.ServerOption{
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	}
	if sb.cfg.MaxConnectionAge.Duration > 0 {
		options = append(options,
			grpc.KeepaliveParams(keepalive.ServerParameters{
				MaxConnectionAge: sb.cfg.MaxConnectionAge.Duration,
			}))
	}

	server := grpc.NewServer(options...)

	for _, service := range sb.services {
		server.RegisterService(service.desc, service.impl)
	}

	start := func() error {
		return filterShutdownErrors(server.Serve(listener))
	}
	stop := func() {
		server.GracefulStop()
	}

	return start, stop, nil
}

// serverMetrics is a struct type used to return a few registered metrics from
// `newServerMetrics`
type serverMetrics struct {
	grpcMetrics *grpc_prometheus.ServerMetrics
	rpcLag      prometheus.Histogram
}

// newServerMetrics registers metrics with a registry. It constructs and
// registers a *grpc_prometheus.ServerMetrics with timing histogram enabled as
// well as a prometheus Histogram for RPC latency. If called more than once on a
// single registry, it will gracefully avoid registering duplicate metrics.
func newServerMetrics(stats prometheus.Registerer) (serverMetrics, error) {
	// Create the grpc prometheus server metrics instance and register it
	grpcMetrics := grpc_prometheus.NewServerMetrics()
	grpcMetrics.EnableHandlingTimeHistogram()
	err := stats.Register(grpcMetrics)
	if err != nil {
		are := prometheus.AlreadyRegisteredError{}
		if errors.As(err, &are) {
			grpcMetrics = are.ExistingCollector.(*grpc_prometheus.ServerMetrics)
		} else {
			return serverMetrics{}, err
		}
	}

	// rpcLag is a prometheus histogram tracking the difference between the time
	// the client sent an RPC and the time the server received it. Create and
	// register it.
	rpcLag := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "grpc_lag",
			Help: "Delta between client RPC send time and server RPC receipt time",
		})
	err = stats.Register(rpcLag)
	if err != nil {
		are := prometheus.AlreadyRegisteredError{}
		if errors.As(err, &are) {
			rpcLag = are.ExistingCollector.(prometheus.Histogram)
		} else {
			return serverMetrics{}, err
		}
	}

	return serverMetrics{
		grpcMetrics: grpcMetrics,
		rpcLag:      rpcLag,
	}, nil
}

// filterShutdownErrors returns the input error, with the exception of "use of
// closed network connection," on which it returns nil
// Per https://github.com/grpc/grpc-go/issues/1017, a gRPC server's `Serve()`
// will always return an error, even when GracefulStop() is called. We don't
// want to log graceful stops as errors, so we filter out the meaningless
// error we get in that situation.
func filterShutdownErrors(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}
