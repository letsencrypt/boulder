package grpc

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
)

// CodedError is a alias required to appease go vet
var CodedError = grpc.Errorf

var errNilMetrics = errors.New("boulder/grpc: received nil ServerMetrics")
var errNilTLS = errors.New("boulder/grpc: received nil tls.Config")

// NewServer creates a gRPC server that uses the provided *tls.Config, and
// verifies that clients present a certificate that (a) is signed by one of
// the configured ClientCAs, and (b) contains at least one
// subjectAlternativeName matching the accepted list from GRPCServerConfig.
func NewServer(c *cmd.GRPCServerConfig, tls *tls.Config, serverMetrics *grpc_prometheus.ServerMetrics) (*grpc.Server, net.Listener, error) {
	if serverMetrics == nil {
		return nil, nil, errNilMetrics
	}
	if tls == nil {
		return nil, nil, errNilTLS
	}
	acceptedSANs := make(map[string]struct{})
	for _, name := range c.ClientNames {
		acceptedSANs[name] = struct{}{}
	}

	creds, err := bcreds.NewServerCredentials(tls, acceptedSANs)
	if err != nil {
		return nil, nil, err
	}

	l, err := net.Listen("tcp", c.Address)
	if err != nil {
		return nil, nil, err
	}

	maxConcurrentStreams := c.MaxConcurrentStreams
	if maxConcurrentStreams == 0 {
		maxConcurrentStreams = 250
	}
	si := &serverInterceptor{serverMetrics}
	return grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(si.intercept),
		grpc.MaxConcurrentStreams(maxConcurrentStreams),
	), l, nil
}

// NewServerMetrics constructs a *grpc_prometheus.ServerMetrics, registered with
// the given registry, with timing histogram enabled. It must be called a
// maximum of once per registry, or there will be conflicting names.
func NewServerMetrics(stats registry) *grpc_prometheus.ServerMetrics {
	metrics := grpc_prometheus.NewServerMetrics()
	metrics.EnableHandlingTimeHistogram()
	stats.MustRegister(metrics)
	return metrics
}
