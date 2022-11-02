package grpc

import (
	"crypto/tls"
	"errors"
	"net"

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

// NewServer creates a gRPC server that uses the provided *tls.Config, and
// verifies that clients present a certificate that (a) is signed by one of
// the configured ClientCAs, and (b) contains at least one
// subjectAlternativeName matching the accepted list from GRPCServerConfig.
func NewServer(c *cmd.GRPCServerConfig, tlsConfig *tls.Config, statsRegistry prometheus.Registerer, clk clock.Clock, interceptors ...grpc.UnaryServerInterceptor) (*grpc.Server, func() error, func(), error) {
	if tlsConfig == nil {
		return nil, nil, nil, errNilTLS
	}

	acceptedSANs := make(map[string]struct{})
	for _, name := range c.ClientNames {
		acceptedSANs[name] = struct{}{}
	}
	for _, service := range c.Services {
		for _, name := range service.ClientNames {
			acceptedSANs[name] = struct{}{}
		}
	}

	metrics, err := newServerMetrics(statsRegistry)
	if err != nil {
		return nil, nil, nil, err
	}

	creds, err := bcreds.NewServerCredentials(tlsConfig, acceptedSANs)
	if err != nil {
		return nil, nil, nil, err
	}

	listener, err := net.Listen("tcp", c.Address)
	if err != nil {
		return nil, nil, nil, err
	}

	si := newServerInterceptor(metrics, clk)
	ac := newServiceAuthChecker(c)

	unaryInterceptors := append([]grpc.UnaryServerInterceptor{
		ac.UnaryInterceptor(),
		si.interceptUnary,
		si.metrics.grpcMetrics.UnaryServerInterceptor(),
		hnygrpc.UnaryServerInterceptor(),
	}, interceptors...)

	streamInterceptors := []grpc.StreamServerInterceptor{
		ac.StreamInterceptor(),
		si.interceptStream,
		si.metrics.grpcMetrics.StreamServerInterceptor(),
		// TODO(#6361): Get a tracing interceptor that works for gRPC streams.
	}

	options := []grpc.ServerOption{
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	}
	if c.MaxConnectionAge.Duration > 0 {
		options = append(options,
			grpc.KeepaliveParams(keepalive.ServerParameters{
				MaxConnectionAge: c.MaxConnectionAge.Duration,
			}))
	}

	server := grpc.NewServer(options...)

	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(server, healthServer)

	start := func() error {
		return cmd.FilterShutdownErrors(server.Serve(listener))
	}
	stop := func() {
		healthServer.Shutdown()
		server.GracefulStop()
	}

	return server, start, stop, nil
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
