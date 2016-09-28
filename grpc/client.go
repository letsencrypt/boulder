package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/jmhodges/clock"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
	"github.com/letsencrypt/boulder/metrics"
)

// CodedError is a alias required to appease go vet
var CodedError = grpc.Errorf

var errNilScope = errors.New("boulder/grpc: received nil scope")

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
	return grpc.Dial(
		"", // Since our staticResolver provides addresses we don't need to pass an address here
		grpc.WithTransportCredentials(bcreds.New(rootCAs, []tls.Certificate{clientCert})),
		grpc.WithBalancer(grpc.RoundRobin(newStaticResolver(c.ServerAddresses))),
		grpc.WithUnaryInterceptor(ci.intercept),
	)
}
