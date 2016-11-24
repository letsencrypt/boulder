package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"

	"github.com/jmhodges/clock"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/metrics"
	"google.golang.org/grpc/credentials"
)

// ClientSetup loads various TLS certificates and creates a
// gRPC TransportCredentials that presents the client certificate
// and validates the certificate presented by the server is for a
// specific hostname and issued by the provided issuer certificate
// thens dials and returns a grpc.ClientConn to the remote service.
func ClientSetup(c *cmd.GRPCClientConfig, stats metrics.Scope) (*grpc.ClientConn, error) {
	if len(c.ServerAddresses) == 0 {
		return nil, fmt.Errorf("boulder/grpc: ServerAddresses is empty")
	}
	if stats == nil {
		return nil, errNilScope
	}
	serverIssuerBytes, err := ioutil.ReadFile(c.ServerIssuerPath)
	if err != nil {
		return nil, err
	}
	rootCAs := x509.NewCertPool()
	if ok := rootCAs.AppendCertsFromPEM(serverIssuerBytes); !ok {
		return nil, fmt.Errorf("Failed to parse server issues from '%s'", c.ServerIssuerPath)
	}
	clientCert, err := tls.LoadX509KeyPair(c.ClientCertificatePath, c.ClientKeyPath)
	if err != nil {
		return nil, err
	}
	ci := clientInterceptor{stats.NewScope("gRPCClient"), clock.Default()}

	//TODO(@cpu): It's janky to only look at the first server address here. Do we
	//need to restore the `clientTransportCredentials`?
	host, _, err := net.SplitHostPort(c.ServerAddresses[0])
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS12, // Override default of tls.VersionTLS10
		MaxVersion:   tls.VersionTLS12, // Same as default in golang <= 1.6
	}
	creds := credentials.NewTLS(tlsConfig)
	creds.OverrideServerName(host)

	return grpc.Dial(
		"", // Since our staticResolver provides addresses we don't need to pass an address here
		grpc.WithTransportCredentials(creds),
		grpc.WithBalancer(grpc.RoundRobin(newStaticResolver(c.ServerAddresses))),
		grpc.WithUnaryInterceptor(ci.intercept),
	)
}
