package main

import (
	"context"
	"errors"
	"flag"
	"sync"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	corepb "github.com/letsencrypt/boulder/core/proto"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/nonce"
	noncepb "github.com/letsencrypt/boulder/nonce/proto"
)

type config struct {
	NonceService struct {
		cmd.ServiceConfig
		Syslog  cmd.SyslogConfig
		MaxUsed int

		RemoteNonceServices []cmd.GRPCClientConfig
	}
}

type nonceServer struct {
	inner          *nonce.NonceService
	remoteServices []noncepb.NonceServiceClient
	log            blog.Logger
}

func (ns *nonceServer) remoteRedeem(ctx context.Context, msg *noncepb.NonceMessage) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		ns.log.Err("Context passed to remoteRedeem does not have a deadline")
		return false
	}
	subCtx, cancel := context.WithDeadline(ctx, deadline.Add(-time.Millisecond*250))
	defer cancel()
	forwarded := true
	msg.Forwarded = &forwarded
	results := make(chan bool, len(ns.remoteServices))
	wg := new(sync.WaitGroup)
	for _, remote := range ns.remoteServices {
		wg.Add(1)
		go func(r noncepb.NonceServiceClient) {
			defer wg.Done()
			resp, err := r.Redeem(subCtx, msg)
			if err != nil {
				ns.log.Errf("remote Redeem call failed: %s", err)
				return
			}
			results <- *resp.Valid
		}(remote)
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	for result := range results {
		select {
		case <-subCtx.Done():
			return false
		default:
			if result {
				return true
			}
		}
	}
	return false
}

func (ns *nonceServer) Redeem(ctx context.Context, msg *noncepb.NonceMessage) (*noncepb.ValidMessage, error) {
	if msg.Nonce == nil {
		return nil, errors.New("Incomplete gRPC request message")
	}
	valid := ns.inner.Valid(*msg.Nonce)
	// If the nonce was not valid, we have configured remote nonce services,
	// and this Redeem message wasn't forwarded, then forward it to the
	// remote services
	if !valid && len(ns.remoteServices) > 0 && msg.Forwarded != nil && !*msg.Forwarded {
		valid = ns.remoteRedeem(ctx, msg)
	}
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
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	if *grpcAddr != "" {
		c.NonceService.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.NonceService.DebugAddr = *debugAddr
	}

	scope, logger := cmd.StatsAndLogging(c.NonceService.Syslog, c.NonceService.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	ns, err := nonce.NewNonceService(scope, c.NonceService.MaxUsed)
	cmd.FailOnError(err, "Failed to initialize nonce service")

	tlsConfig, err := c.NonceService.TLS.Load()
	cmd.FailOnError(err, "tlsConfig config")

	nonceServer := &nonceServer{inner: ns, log: logger}
	if len(c.NonceService.RemoteNonceServices) > 0 {
		clientMetrics := bgrpc.NewClientMetrics(scope)
		clk := cmd.Clock()
		for _, remoteNonceConfig := range c.NonceService.RemoteNonceServices {
			rnsConn, err := bgrpc.ClientSetup(&remoteNonceConfig, tlsConfig, clientMetrics, clk)
			cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to Nonce service")
			nonceServer.remoteServices = append(nonceServer.remoteServices, noncepb.NewNonceServiceClient(rnsConn))
		}
	}

	serverMetrics := bgrpc.NewServerMetrics(scope)
	grpcSrv, l, err := bgrpc.NewServer(c.NonceService.GRPC, tlsConfig, serverMetrics, cmd.Clock())
	cmd.FailOnError(err, "Unable to setup nonce service gRPC server")
	noncepb.RegisterNonceServiceServer(grpcSrv, nonceServer)

	go cmd.CatchSignals(logger, grpcSrv.GracefulStop)

	err = cmd.FilterShutdownErrors(grpcSrv.Serve(l))
	cmd.FailOnError(err, "Nonce service gRPC server failed")
}
