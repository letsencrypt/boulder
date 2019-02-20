package main

import (
	"context"
	"flag"

	"github.com/letsencrypt/boulder/cmd"
	corepb "github.com/letsencrypt/boulder/core/proto"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/nonce"
	noncepb "github.com/letsencrypt/boulder/nonce/proto"
)

type config struct {
	NonceService struct {
		cmd.ServiceConfig
	}
	Syslog cmd.SyslogConfig
}

type nonceServer struct {
	inner *nonce.NonceService
}

func (ns *nonceServer) Valid(_ context.Context, msg *noncepb.NonceMessage) (*noncepb.ValidMessage, error) {
	if msg.Nonce == nil {
		return nil, bgrpc.ErrIncompleteRequest
	}
	valid := ns.inner.Valid(*msg.Nonce)
	return &noncepb.ValidMessage{Valid: &valid}, nil
}

func (ns *nonceServer) Nonce(_ context.Context, _ *corepb.Empty) (*noncepb.NonceMessage, error) {
	nonce, err := ns.inner.Nonce()
	if err != nil {
		return nil, err
	}
	return &noncepb.NonceMessage{Nonce: &nonce}, nil
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.NonceService.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	ns, err := nonce.NewNonceService(scope)
	cmd.FailOnError(err, "Failed to initialize nonce service")

	tlsConfig, err := c.NonceService.TLS.Load()
	cmd.FailOnError(err, "tlsConfig config")
	serverMetrics := bgrpc.NewServerMetrics(scope)
	grpcSrv, l, err := bgrpc.NewServer(c.NonceService.GRPC, tlsConfig, serverMetrics, cmd.Clock())
	cmd.FailOnError(err, "Unable to setup nonce service gRPC server")
	noncepb.RegisterNonceServiceServer(grpcSrv, &nonceServer{inner: ns})

	go cmd.CatchSignals(logger, grpcSrv.GracefulStop)

	err = cmd.FilterShutdownErrors(grpcSrv.Serve(l))
	cmd.FailOnError(err, "Nonce service gRPC server failed")
}
