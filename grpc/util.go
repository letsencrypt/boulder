package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/google.golang.org/grpc"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/google.golang.org/grpc/credentials"

	"github.com/letsencrypt/boulder/cmd"
)

// CodedError is a alias required to appease go vet
var CodedError = grpc.Errorf

// ClientSetup loads various TLS certificates and creates a
// gRPC TransportAuthenticator that presents the client certificate
// and validates the certificate presented by the server is for a
// specific hostname and issued by the provided issuer certificate
// thens dials and returns a grpc.ClientConn to the remote service.
func ClientSetup(c *cmd.GRPCClientConfig) (*grpc.ClientConn, error) {
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

	return grpc.Dial(c.ServerAddress, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		ServerName:   c.ServerHostname,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{clientCert},
	})))
}
