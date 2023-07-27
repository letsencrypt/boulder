//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/jmhodges/clock"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/letsencrypt/boulder/cmd"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/nonce"
	"github.com/letsencrypt/boulder/test"
)

type Config struct {
	WebFooEnd struct {
		TLS cmd.TLSConfig
		// CaseOne config will have 2 SRV records. The first will have 0
		// backends, the second will have 1.
		CaseOne *cmd.GRPCClientConfig

		// CaseTwo config will have 2 SRV records. The first will not be
		// configured in Consul, the second will have 1 backend.
		CaseTwo *cmd.GRPCClientConfig

		// CaseThree config will have 2 SRV records. Neither will be
		// configured in Consul.
		CaseThree *cmd.GRPCClientConfig

		// CaseFour config will have 2 SRV records. Neither will have
		// backends.
		CaseFour *cmd.GRPCClientConfig
	}
}

func TestSRVResolver_CaseOne(t *testing.T) {
	t.Parallel()

	var c Config
	err := cmd.ReadConfigFile("test/integration/testdata/srv-resolver-config.json", &c)
	test.AssertNotError(t, err, "Could not read config file")

	tlsConfig, err := c.WebFooEnd.TLS.Load(metrics.NoopRegisterer)
	test.AssertNotError(t, err, "Could not load TLS config")
	clk := clock.New()

	// This should succeed, even though the first SRV record has no backends.
	getNonceConn1, err := bgrpc.ClientSetup(c.WebFooEnd.CaseOne, tlsConfig, metrics.NoopRegisterer, clk)
	test.AssertNotError(t, err, "Could not set up gRPC client")
	gnc1 := nonce.NewGetter(getNonceConn1)
	_, err = gnc1.Nonce(context.Background(), &emptypb.Empty{})
	test.AssertNotError(t, err, "Unexpected error getting nonce")
}

func TestSRVResolver_CaseTwo(t *testing.T) {
	t.Parallel()

	var c Config
	err := cmd.ReadConfigFile("test/integration/testdata/srv-resolver-config.json", &c)
	test.AssertNotError(t, err, "Could not read config file")

	tlsConfig, err := c.WebFooEnd.TLS.Load(metrics.NoopRegisterer)
	test.AssertNotError(t, err, "Could not load TLS config")
	clk := clock.New()

	// This should succeed, even though the first SRV record is not configured
	// in Consul.
	getNonceConn2, err := bgrpc.ClientSetup(c.WebFooEnd.CaseTwo, tlsConfig, metrics.NoopRegisterer, clk)
	test.AssertNotError(t, err, "Could not set up gRPC client")
	gnc2 := nonce.NewGetter(getNonceConn2)
	_, err = gnc2.Nonce(context.Background(), &emptypb.Empty{})
	test.AssertNotError(t, err, "Unexpected error getting nonce")
}

func TestSRVResolver_CaseThree(t *testing.T) {
	t.Parallel()

	var c Config
	err := cmd.ReadConfigFile("test/integration/testdata/srv-resolver-config.json", &c)
	test.AssertNotError(t, err, "Could not read config file")

	tlsConfig, err := c.WebFooEnd.TLS.Load(metrics.NoopRegisterer)
	test.AssertNotError(t, err, "Could not load TLS config")
	clk := clock.New()

	// This should fail, because neither SRV record is configured in Consul and
	// the resolver will not return any backends.
	getNonceConn3, err := bgrpc.ClientSetup(c.WebFooEnd.CaseThree, tlsConfig, metrics.NoopRegisterer, clk)
	test.AssertNotError(t, err, "Could not set up gRPC client")
	gnc3 := nonce.NewGetter(getNonceConn3)
	_, err = gnc3.Nonce(context.Background(), &emptypb.Empty{})
	test.AssertNotError(t, err, "Unexpected error getting nonce")
}

func TestSRVResolver_CaseFour(t *testing.T) {
	t.Parallel()

	var c Config
	err := cmd.ReadConfigFile("test/integration/testdata/srv-resolver-config.json", &c)
	test.AssertNotError(t, err, "Could not read config file")

	tlsConfig, err := c.WebFooEnd.TLS.Load(metrics.NoopRegisterer)
	test.AssertNotError(t, err, "Could not load TLS config")
	clk := clock.New()

	// This should fail, because neither SRV record has any backends.
	getNonceConn4, err := bgrpc.ClientSetup(c.WebFooEnd.CaseFour, tlsConfig, metrics.NoopRegisterer, clk)
	test.AssertNotError(t, err, "Could not set up gRPC client")
	gnc4 := nonce.NewGetter(getNonceConn4)
	_, err = gnc4.Nonce(context.Background(), &emptypb.Empty{})
	test.AssertNotError(t, err, "Unexpected error getting nonce")
}
