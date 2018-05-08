package grpc

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
)

// ClientSetup creates a gRPC TransportCredentials that presents
// a client certificate and validates the the server certificate based
// on the provided *tls.Config.
// It dials the remote service and returns a grpc.ClientConn if successful.
func ClientSetup(c *cmd.GRPCClientConfig, tls *tls.Config, metrics clientMetrics, clk clock.Clock) (*grpc.ClientConn, error) {
	if len(c.ServerAddresses) == 0 {
		return nil, fmt.Errorf("boulder/grpc: ServerAddresses is empty")
	}
	if tls == nil {
		return nil, errNilTLS
	}

	ci := clientInterceptor{c.Timeout.Duration, metrics, clk}
	// When there's only one server address, we use our custom newDNSResolver,
	// intended as a temporary shim until we upgrade to a version of gRPC that has
	// its own built-in DNS resolver. This works equally well when there's only
	// one IP for a hostname or when there are multiple IPs for the hostname.
	if len(c.ServerAddresses) == 1 {
		host, port, err := net.SplitHostPort(c.ServerAddresses[0])
		if err != nil {
			return nil, err
		}
		creds := bcreds.NewClientCredentials(tls.RootCAs, tls.Certificates, host)
		return grpc.Dial(
			c.ServerAddresses[0],
			grpc.WithTransportCredentials(creds),
			grpc.WithBalancer(grpc.RoundRobin(newDNSResolver(host, port))),
			grpc.WithUnaryInterceptor(ci.intercept),
		)
	} else {
		creds := bcreds.NewClientCredentials(tls.RootCAs, tls.Certificates, "")
		return grpc.Dial(
			"", // Since our staticResolver provides addresses we don't need to pass an address here
			grpc.WithTransportCredentials(creds),
			grpc.WithBalancer(grpc.RoundRobin(newStaticResolver(c.ServerAddresses))),
			grpc.WithUnaryInterceptor(ci.intercept),
		)
	}
}

type registry interface {
	MustRegister(...prometheus.Collector)
}

// clientMetrics is a struct type used to return registered metrics from
// `NewClientMetrics`
type clientMetrics struct {
	grpcMetrics *grpc_prometheus.ClientMetrics
	// inFlightRPCs is a labelled gauge that slices by service/method the number
	// of outstanding/in-flight RPCs.
	inFlightRPCs *prometheus.GaugeVec
}

// NewClientMetrics constructs a *grpc_prometheus.ClientMetrics, registered with
// the given registry, with timing histogram enabled. It must be called a
// maximum of once per registry, or there will be conflicting names.
func NewClientMetrics(stats registry) clientMetrics {
	// Create the grpc prometheus client metrics instance and register it
	grpcMetrics := grpc_prometheus.NewClientMetrics()
	grpcMetrics.EnableClientHandlingTimeHistogram()
	stats.MustRegister(grpcMetrics)

	// Create a gauge to track in-flight RPCs and register it.
	inFlightGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "grpc_in_flight",
		Help: "Number of in-flight (sent, not yet completed) RPCs",
	}, []string{"method", "service"})
	stats.MustRegister(inFlightGauge)

	return clientMetrics{
		grpcMetrics:  grpcMetrics,
		inFlightRPCs: inFlightGauge,
	}
}
