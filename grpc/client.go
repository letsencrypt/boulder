package grpc

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
)

// ClientSetup creates a gRPC TransportCredentials that presents
// a client certificate and validates the the server certificate based
// on the provided *tls.Config.
// It dials the remote service and returns a grpc.ClientConn if successful.
func ClientSetup(c *cmd.GRPCClientConfig, tlsConfig *tls.Config, metrics clientMetrics, clk clock.Clock) (*grpc.ClientConn, error) {
	if c.ServerAddress == "" {
		return nil, errors.New("ServerAddress is empty")
	}
	if tlsConfig == nil {
		return nil, errNilTLS
	}

	// Set the only acceptable TLS version to 1.2 and the only acceptable cipher suite
	// to ECDHE-RSA-CHACHA20-POLY1305.
	tlsConfig.MinVersion, tlsConfig.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	tlsConfig.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305}

	ci := clientInterceptor{c.Timeout.Duration, metrics, clk}
	host, _, err := net.SplitHostPort(c.ServerAddress)
	if err != nil {
		return nil, err
	}
	creds := bcreds.NewClientCredentials(tlsConfig.RootCAs, tlsConfig.Certificates, host)
	return grpc.Dial(
		"dns:///"+c.ServerAddress,
		grpc.WithBalancerName("round_robin"),
		grpc.WithTransportCredentials(creds),
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
		Name: "grpc_in_flight",
		Help: "Number of in-flight (sent, not yet completed) RPCs",
	}, []string{"method", "service"})
	stats.MustRegister(inFlightGauge)

	return clientMetrics{
		grpcMetrics:  grpcMetrics,
		inFlightRPCs: inFlightGauge,
	}
}
