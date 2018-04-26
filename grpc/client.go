package grpc

import (
	"crypto/tls"
	"fmt"

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
		Name: "in_flight_rpcs",
		Help: "Number of in-flight (sent, not yet completed) RPCs",
	}, []string{"method", "service"})
	stats.MustRegister(inFlightGauge)

	return clientMetrics{
		grpcMetrics:  grpcMetrics,
		inFlightRPCs: inFlightGauge,
	}
}
