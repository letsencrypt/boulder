package grpc

import (
	"crypto/tls"
	"fmt"

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/jmhodges/clock"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
	"github.com/letsencrypt/boulder/metrics"
)

// ClientSetup creates a gRPC TransportCredentials that presents
// a client certificate and validates the the server certificate based
// on the provided *tls.Config.
// It dials the remote service and returns a grpc.ClientConn if successful.
func ClientSetup(c *cmd.GRPCClientConfig, tls *tls.Config, stats metrics.Scope) (*grpc.ClientConn, error) {
	if len(c.ServerAddresses) == 0 {
		return nil, fmt.Errorf("boulder/grpc: ServerAddresses is empty")
	}
	if stats == nil {
		return nil, errNilScope
	}
	if tls == nil {
		return nil, errNilTLS
	}

	grpc_prometheus.EnableClientHandlingTimeHistogram()

	ci := clientInterceptor{stats.NewScope("gRPCClient"), clock.Default(), c.Timeout.Duration}
	creds := bcreds.NewClientCredentials(tls.RootCAs, tls.Certificates)
	return grpc.Dial(
		"", // Since our staticResolver provides addresses we don't need to pass an address here
		grpc.WithTransportCredentials(creds),
		grpc.WithBalancer(grpc.RoundRobin(newStaticResolver(c.ServerAddresses))),
		grpc.WithUnaryInterceptor(ci.intercept),
	)
}
