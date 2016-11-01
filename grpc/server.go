package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net"

	"github.com/jmhodges/clock"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
	"github.com/letsencrypt/boulder/metrics"
)

// CodedError is a alias required to appease go vet
var CodedError = grpc.Errorf

var errNilScope = errors.New("boulder/grpc: received nil scope")

// NewServer loads various TLS certificates and creates a
// gRPC Server that verifies the client certificate was
// issued by the provided issuer certificate and presents a
// a server TLS certificate.
func NewServer(c *cmd.GRPCServerConfig, stats metrics.Scope) (*grpc.Server, net.Listener, error) {
	if stats == nil {
		return nil, nil, errNilScope
	}
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
	servTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}

	whitelist := make(map[string]struct{})
	for _, subjCN := range c.ClientWhitelist {
		whitelist[subjCN] = struct{}{}
	}

	creds := bcreds.New(nil, servTLSConfig, whitelist)
	l, err := net.Listen("tcp", c.Address)
	if err != nil {
		return nil, nil, err
	}

	si := &serverInterceptor{stats.NewScope("gRPCServer"), clock.Default()}
	return grpc.NewServer(grpc.Creds(creds), grpc.UnaryInterceptor(si.intercept)), l, nil
}
