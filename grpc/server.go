package grpc

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/jmhodges/clock"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
	"github.com/letsencrypt/boulder/metrics"
)

// CodedError is a alias required to appease go vet
var CodedError = grpc.Errorf

var errNilScope = errors.New("boulder/grpc: received nil scope")
var errNilTLS = errors.New("boulder/grpc: received nil tls.Config")

// NewServer creates a gRPC server that uses the provided *tls.Config, and
// verifies that clients present a certificate that (a) is signed by one of
// the configured ClientCAs, and (b) contains at least one
// subjectAlternativeName matching the accepted list from GRPCServerConfig.
func NewServer(c *cmd.GRPCServerConfig, tls *tls.Config, stats metrics.Scope) (*grpc.Server, net.Listener, error) {
	if stats == nil {
		return nil, nil, errNilScope
	}
	if tls == nil {
		return nil, nil, errNilTLS
	}
	acceptedSANs := make(map[string]struct{})
	for _, name := range c.ClientNames {
		acceptedSANs[name] = struct{}{}
	}

	creds, err := bcreds.NewServerCredentials(tls, acceptedSANs)
	if err != nil {
		return nil, nil, err
	}

	l, err := net.Listen("tcp", c.Address)
	if err != nil {
		return nil, nil, err
	}

	grpc_prometheus.EnableHandlingTimeHistogram()

	si := &serverInterceptor{stats.NewScope("gRPCServer"), clock.Default()}
	return grpc.NewServer(grpc.Creds(creds), grpc.UnaryInterceptor(si.intercept)), l, nil
}
