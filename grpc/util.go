package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

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
	host, _, err := net.SplitHostPort(c.ServerAddress)
	if err != nil {
		return nil, err
	}
	return grpc.Dial(c.ServerAddress, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		ServerName:   host,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{clientCert},
	})))
}

// NewServer loads various TLS certificates and creates a
// gRPC Server that verifies the client certificate was
// issued by the provided issuer certificate and presents a
// a server TLS certificate.
func NewServer(c *cmd.GRPCServerConfig) (*grpc.Server, net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(c.ServerCertificatePath, c.ServerKeyPath)
	if err != nil {
		return nil, nil, err
	}
	clientIssuerBytes, err := ioutil.ReadFile(c.ClientIssuerPath)
	if err != nil {
		return nil, nil, err
	}
	clientCAs := x509.NewCertPool()
	if ok := clientCAs.AppendCertsFromPEM(clientIssuerBytes); !ok {
		return nil, nil, errors.New("Failed to parse client issuer certificates")
	}
	servConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	creds := credentials.NewTLS(servConf)
	l, err := net.Listen("tcp", c.Address)
	if err != nil {
		return nil, nil, err
	}
	return grpc.NewServer(grpc.Creds(creds)), l, nil
}
