package grpc

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"

	// Import for its init function, which causes clients to rely on the
	// Health Service for load-balancing.
	"google.golang.org/grpc/balancer/roundrobin"
	_ "google.golang.org/grpc/health"
)

// ClientSetup creates a gRPC TransportCredentials that presents
// a client certificate and validates the the server certificate based
// on the provided *tls.Config.
// It dials the remote service and returns a grpc.ClientConn if successful.
func ClientSetup(c *cmd.GRPCClientConfig, tlsConfig *tls.Config, metrics clientMetrics, clk clock.Clock, interceptors ...grpc.UnaryClientInterceptor) (*grpc.ClientConn, error) {
	if c == nil {
		return nil, errors.New("nil gRPC client config provided. JSON config is probably missing a fooService section.")
	}
	if c.ServerIPAddresses != nil && c.ServerAddress != "" {
		return nil, errors.New(
			"both 'serverIPAddresses' and 'serverAddress' are set in gRPC client config provided. Only one should be set.",
		)
	}
	if tlsConfig == nil {
		return nil, errNilTLS
	}

	ci := clientInterceptor{c.Timeout.Duration, metrics, clk}

	unaryInterceptors := append(interceptors, []grpc.UnaryClientInterceptor{
		ci.interceptUnary,
		ci.metrics.grpcMetrics.UnaryClientInterceptor(),
		otelgrpc.UnaryClientInterceptor(),
	}...)

	streamInterceptors := []grpc.StreamClientInterceptor{
		ci.interceptStream,
		ci.metrics.grpcMetrics.StreamClientInterceptor(),
		otelgrpc.StreamClientInterceptor(),
	}

	var target string
	var hostOverride string
	if c.ServerAddress != "" {
		var splitHostPortErr error
		hostOverride, _, splitHostPortErr = net.SplitHostPort(c.ServerAddress)
		if splitHostPortErr != nil {
			return nil, splitHostPortErr
		}
		target = "dns:///" + c.ServerAddress
	} else {
		target = "static:///" + strings.Join(c.ServerIPAddresses, ",")
	}
	creds := bcreds.NewClientCredentials(tlsConfig.RootCAs, tlsConfig.Certificates, hostOverride)
	return grpc.Dial(
		target,
		grpc.WithDefaultServiceConfig(fmt.Sprintf(`{"loadBalancingConfig": [{"%s":{}}]}`, roundrobin.Name)),
		grpc.WithTransportCredentials(creds),
		grpc.WithChainUnaryInterceptor(unaryInterceptors...),
		grpc.WithChainStreamInterceptor(streamInterceptors...),
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
