package main

import (
	"crypto/tls"
	"flag"
	"os"

	ct "github.com/google/certificate-transparency/go"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/publisher"
	pubPB "github.com/letsencrypt/boulder/publisher/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

const clientName = "Publisher"

type config struct {
	Publisher struct {
		cmd.ServiceConfig
		SubmissionTimeout cmd.ConfigDuration
		SAService         *cmd.GRPCClientConfig
		Features          map[string]bool
	}

	Statsd cmd.StatsdConfig

	Syslog cmd.SyslogConfig

	Common struct {
		CT struct {
			Logs                       []cmd.LogDescription
			IntermediateBundleFilename string
		}
	}
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")
	err = features.Set(c.Publisher.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	stats, logger := cmd.StatsAndLogging(c.Statsd, c.Syslog)
	scope := metrics.NewStatsdScope(stats, "Publisher")
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString(clientName))

	logs := make([]*publisher.Log, len(c.Common.CT.Logs))
	for i, ld := range c.Common.CT.Logs {
		logs[i], err = publisher.NewLog(ld.URI, ld.Key, logger)
		cmd.FailOnError(err, "Unable to parse CT log description")
	}

	if c.Common.CT.IntermediateBundleFilename == "" {
		logger.AuditErr("No CT submission bundle provided")
		os.Exit(1)
	}
	pemBundle, err := core.LoadCertBundle(c.Common.CT.IntermediateBundleFilename)
	cmd.FailOnError(err, "Failed to load CT submission bundle")
	bundle := []ct.ASN1Cert{}
	for _, cert := range pemBundle {
		bundle = append(bundle, ct.ASN1Cert(cert.Raw))
	}

	// TODO(jsha): Publisher is currently configured in production using old-style
	// GRPC config fields. Remove this once production is switched over.
	if c.Publisher.GRPC != nil && c.Publisher.TLS.CertFile == nil {
		c.Publisher.TLS = cmd.TLSConfig{
			CertFile:   &c.Publisher.GRPC.ServerCertificatePath,
			KeyFile:    &c.Publisher.GRPC.ServerKeyPath,
			CACertFile: &c.Publisher.GRPC.ClientIssuerPath,
		}
	}

	var tls *tls.Config
	if c.Publisher.TLS.CertFile != nil {
		tls, err = c.Publisher.TLS.Load()
		cmd.FailOnError(err, "TLS config")
	}

	conn, err := bgrpc.ClientSetup(c.Publisher.SAService, tls, scope)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(conn))

	pubi := publisher.New(
		bundle,
		logs,
		c.Publisher.SubmissionTimeout.Duration,
		logger,
		scope,
		sac)

	var grpcSrv *grpc.Server
	if c.Publisher.GRPC != nil {
		s, l, err := bgrpc.NewServer(c.Publisher.GRPC, tls, scope)
		cmd.FailOnError(err, "Unable to setup Publisher gRPC server")
		gw := bgrpc.NewPublisherServerWrapper(pubi)
		pubPB.RegisterPublisherServer(s, gw)
		go func() {
			err = s.Serve(l)
			cmd.FailOnError(err, "Publisher gRPC service failed")
		}()
		grpcSrv = s
	}

	go cmd.CatchSignals(logger, func() {
		if grpcSrv != nil {
			grpcSrv.GracefulStop()
		}
	})

	go cmd.DebugServer(c.Publisher.DebugAddr)
	go cmd.ProfileCmd(scope)

	select {}
}
