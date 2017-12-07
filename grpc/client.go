package grpc

import (
	"crypto/tls"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
)

// ClientSetup creates a gRPC TransportCredentials that presents
// a client certificate and validates the the server certificate based
// on the provided *tls.Config.
// It dials the remote service and returns a grpc.ClientConn if successful.
func ClientSetup(c *cmd.GRPCClientConfig, tls *tls.Config, clientMetrics *grpc_prometheus.ClientMetrics) (*grpc.ClientConn, error) {
	if len(c.ServerAddresses) == 0 {
		return nil, fmt.Errorf("boulder/grpc: ServerAddresses is empty")
	}
	if tls == nil {
		return nil, errNilTLS
	}

	ci := clientInterceptor{c.Timeout.Duration, clientMetrics}
	creds := bcreds.NewClientCredentials(tls.RootCAs, tls.Certificates)
	return grpc.Dial(
		"", // Since our staticResolver provides addresses we don't need to pass an address here
		grpc.WithTransportCredentials(creds),
		grpc.WithBalancer(grpc.RoundRobin(newStaticResolver(c.ServerAddresses))),
		grpc.WithUnaryInterceptor(ci.intercept),
	)
}

type registry interface {
	MustRegister(...prometheus.Collector)
}

// NewClientMetrics constructs a *grpc_prometheus.ClientMetrics, registered with
// the given registry, with timing histogram enabled. It must be called a
// maximum of once per registry, or there will be conflicting names.
func NewClientMetrics(stats registry) *grpc_prometheus.ClientMetrics {
	metrics := grpc_prometheus.NewClientMetrics()
	metrics.EnableClientHandlingTimeHistogram()
	stats.MustRegister(metrics)
	return metrics
}
