// vaCommon contains setup functions shared between the VA and Remote VAs (RVA).
package vaCommon

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	bgrpc "github.com/letsencrypt/boulder/grpc"
	vapb "github.com/letsencrypt/boulder/va/proto"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/va"
)

// SetupServerResolvers returns a bdns.ServerProvider or an error.
func SetupServerResolvers(staticResolvers []string, dynamicProvider *cmd.DNSProvider) (bdns.ServerProvider, error) {
	proto := "udp"
	if features.Get().DOH {
		proto = "tcp"
	}

	var servers bdns.ServerProvider
	var err error
	if len(staticResolvers) != 0 {
		servers, err = bdns.NewStaticProvider(staticResolvers)
		if err != nil {
			return nil, fmt.Errorf("Couldn't start static DNS server resolver: %s", err)
		}
	} else {
		servers, err = bdns.StartDynamicProvider(dynamicProvider, 60*time.Second, proto)
		if err != nil {
			return nil, fmt.Errorf("Couldn't start dynamic DNS server resolver: %s", err)
		}
	}

	return servers, nil
}

// SetupClientResolver creates a boulder DNS client used to query upstream
// resolvers.
func SetupClientResolver(dnsTimeout time.Duration, servers bdns.ServerProvider, scope prometheus.Registerer, clk clock.Clock, dnsTries int, logger blog.Logger, tlsConfig *tls.Config, allowLoopbackAddrs bool) bdns.Client {
	if dnsTries < 1 {
		dnsTries = 1
	}

	var resolver bdns.Client
	if allowLoopbackAddrs {
		resolver = bdns.NewTest(
			dnsTimeout,
			servers,
			scope,
			clk,
			dnsTries,
			logger,
			tlsConfig)
	} else {
		resolver = bdns.New(
			dnsTimeout,
			servers,
			scope,
			clk,
			dnsTries,
			logger,
			tlsConfig)
	}

	return resolver
}

// SetupNewVAImplAndStartServer creates a new VA implementation and a gRPC
// server. It returns a function to be used to start said gRPC server or an
// error.
func SetupNewVAImplAndStartServer(resolver bdns.Client, remotes []va.RemoteVA, maxValidationFailures int, userAgent string, issuerDomain string, scope prometheus.Registerer, clk clock.Clock, logger blog.Logger, accountURIPrefixes []string, grpcSrvConfig *cmd.GRPCServerConfig, tlsConfig *tls.Config) (func() error, error) {
	vai, err := va.NewValidationAuthorityImpl(
		resolver,
		remotes,
		maxValidationFailures,
		userAgent,
		issuerDomain,
		scope,
		clk,
		logger,
		accountURIPrefixes)
	if err != nil {
		return nil, fmt.Errorf("Unable to create VA server: %s", err)
	}

	start, err := bgrpc.NewServer(grpcSrvConfig, logger).Add(
		&vapb.VA_ServiceDesc, vai).Add(
		&vapb.CAA_ServiceDesc, vai).Build(tlsConfig, scope, clk)
	if err != nil {
		return nil, fmt.Errorf("Unable to setup gRPC server: %s", err)
	}

	return start, nil
}
