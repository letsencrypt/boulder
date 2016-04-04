package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"

	"github.com/letsencrypt/boulder/cmd"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/google.golang.org/grpc/credentials"
)

// LoadClientCreds loads various TLS certificates and creates a
// gRPC TransportAuthenticator that presents the client certificate
// and validates the certificate presented by the server is for a
// specific hostname and issued by the provided issuer certificate.
func LoadClientCreds(c *cmd.GRPCClientConfig) (credentials.TransportAuthenticator, error) {
	serverIssuerBytes, err := ioutil.ReadFile(c.ServerIssuerPath)
	if err != nil {
		return nil, err
	}
	serverIssuer, err := x509.ParseCertificate(serverIssuerBytes)
	if err != nil {
		return nil, err
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(serverIssuer)
	clientCert, err := tls.LoadX509KeyPair(c.ClientCertificatePath, c.ClientKeyPath)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(&tls.Config{
		ServerName:   c.ServerHostname,
		RootCAs:      rootCAs,
		Certificates: []tls.Certificate{clientCert},
	}), nil
}
