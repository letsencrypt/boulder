package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"io"
	"math/big"
	mrand "math/rand"
	"os"
	"sync"
	"time"

	"github.com/honeycombio/beeline-go"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/letsencrypt/boulder/cmd"
	crlpb "github.com/letsencrypt/boulder/cmd/crls-poc/proto"
	"github.com/letsencrypt/boulder/cmd/crls-poc/server"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
)

type Config struct {
	Common struct {
		cmd.ServiceConfig
		Features map[string]bool
	}

	Server struct {
		GRPCCRLGenerator *cmd.GRPCServerConfig

		// Issuers is a list of all issuers which can sign CRLs.
		Issuers []issuance.IssuerConfig

		// LifespanCRL is how long CRLs are valid for. Per the BRs, Section 4.9.7,
		// it MUST NOT be more than 10 days.
		LifespanCRL cmd.ConfigDuration
	}

	Client struct {
		CRLService *cmd.GRPCClientConfig
	}

	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(c.Common.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	tlsConfig, err := c.Common.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.Common.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())
	clk := cmd.Clock()

	bc, err := c.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

	// Set up the proof-of-concept gRPC server.
	issuers := make([]*issuance.Issuer, 0, len(c.Server.Issuers))
	for _, issuerConfig := range c.Server.Issuers {
		cert, signer, err := issuance.LoadIssuer(issuerConfig.Location)
		cmd.FailOnError(err, "Failed to load issuer")
		issuers = append(issuers, &issuance.Issuer{Cert: cert, Signer: signer})
	}

	ci, err := server.NewCRLImpl(issuers, c.Server.LifespanCRL.Duration, logger)
	cmd.FailOnError(err, "Failed to create CRL impl")

	serverMetrics := bgrpc.NewServerMetrics(scope)

	crlSrv, crlListener, err := bgrpc.NewServer(c.Server.GRPCCRLGenerator, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup CA gRPC server")

	crlpb.RegisterCRLGeneratorServer(crlSrv, ci)

	crlHealth := health.NewServer()
	healthpb.RegisterHealthServer(crlSrv, crlHealth)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		cmd.FailOnError(cmd.FilterShutdownErrors(crlSrv.Serve(crlListener)),
			"CRLGenerator gRPC service failed")
		wg.Done()
	}()

	go cmd.CatchSignals(logger, func() {
		crlHealth.Shutdown()
		crlSrv.GracefulStop()
		wg.Wait()
	})

	// Set up the proof-of-concept gRPC client.
	clientMetrics := bgrpc.NewClientMetrics(scope)

	conn, err := bgrpc.ClientSetup(c.Client.CRLService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to CRLGenerator")
	cc := crlpb.NewCRLGeneratorClient(conn)

	// Make a call to see if it works! Stream a bunch of random serials and
	// statuses across, then read all the bytes back. Not using a goroutine
	// because we know the server side is synchronous and won't start sending
	// responses until the input stream is complete.
	stream, err := cc.GenerateCRL(context.Background())
	cmd.FailOnError(err, "Failed to create gRPC stream")

	err = stream.Send(&crlpb.GenerateCRLRequest{
		Payload: &crlpb.GenerateCRLRequest_Metadata{
			Metadata: &crlpb.CRLMetadata{
				IssuerNameID: int64(issuers[0].Cert.NameID()),
				ThisUpdate:   clk.Now().UnixNano(),
			},
		},
	})
	cmd.FailOnError(err, "Failed to send metadata")

	numEntries := 100_000

	for i := 0; i < numEntries; i++ {
		var serialBytes [16]byte
		_, _ = rand.Read(serialBytes[:])
		serial := big.NewInt(0).SetBytes(serialBytes[:])
		serialString := core.SerialToString(serial)

		reason := int32(mrand.Intn(10))

		ninetyDays := time.Duration(90 * 24 * time.Hour)
		earliest := clk.Now().Add(-ninetyDays).UnixNano()
		revokedAt := time.Unix(0, earliest+mrand.Int63n(ninetyDays.Nanoseconds())).UnixNano()

		err = stream.Send(&crlpb.GenerateCRLRequest{
			Payload: &crlpb.GenerateCRLRequest_Entry{
				Entry: &crlpb.CRLEntry{
					Serial:    serialString,
					Reason:    reason,
					RevokedAt: revokedAt,
				},
			},
		})
		cmd.FailOnError(err, "Failed to send crl entry")
	}
	err = stream.CloseSend()
	cmd.FailOnError(err, "Failed to close send stream")

	crlBytes := make([]byte, 0)
	for {
		out, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				break
			}
			cmd.FailOnError(err, "Failed to read from response stream")
		}

		crlBytes = append(crlBytes, out.Chunk...)
	}

	crl, err := x509.ParseDERCRL(crlBytes)
	cmd.FailOnError(err, "Failed to parse CRL bytes")

	err = issuers[0].Cert.CheckCRLSignature(crl)
	cmd.FailOnError(err, "Failed to validate CRL signature")

	if len(crl.TBSCertList.RevokedCertificates) != numEntries {
		cmd.Fail("Got wrong number of entries back in CRL")
	}

	// for _, entry := range crl.TBSCertList.RevokedCertificates {
	// 	fmt.Printf("%s: %s\n", core.SerialToString(entry.SerialNumber), entry.RevocationTime)
	// }
}
