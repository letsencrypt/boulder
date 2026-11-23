package notmain

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/blog"
	"github.com/letsencrypt/boulder/bs3"
	"github.com/letsencrypt/boulder/ca"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
	mtca "github.com/letsencrypt/boulder/mtca"
	mtcapb "github.com/letsencrypt/boulder/mtca/proto"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/treedb"
)

type Config struct {
	MTCA struct {
		cmd.ServiceConfig

		GRPCMTCA *cmd.GRPCServerConfig

		DB cmd.DBConfig `validate:"required"`
		S3 bs3.Config   `validate:"required"`

		// LogID identifies the issuance log this MTCA sequences. Its CA ID must
		// match the issuer certificate's.
		LogID issuancelog.Config `validate:"required"`

		Issuance struct {
			CRLProfile issuance.CRLProfileConfig `validate:"required"`

			CertProfiles map[string]issuance.ProfileConfig `validate:"required,dive,keys,alphanum,min=1,max=32,endkeys"`
			// Issuers holds the configuration for all MTC issuers.
			//
			// The MTCA is responsible for both issuing certificates and signing
			// CRLs. For issuing certificates, only one MTCA per issuer may be
			// active at a time, which is expressed by having a non-empty list
			// of profiles. The issuers that are only present for CRL signing
			// should have an empty list of profiles. This is checked at startup.
			Issuers []issuance.IssuerConfig `validate:"min=1,dive"`
		}

		// SequencingPeriod controls how frequently the MTCA sequences a batch and signs a checkpoint.
		SequencingPeriod config.Duration `validate:"required"`
	}

	Syslog        blog.Config
	OpenTelemetry cmd.OpenTelemetryConfig
}

func main() {
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	// We require an explicit flag to initialize a log because this is a rare operation and we want
	// to make sure it's intentional. We exit after initializing the log to make sure we don't
	// accidentally include `-init-log` in the command intended for general server operation.
	initLog := flag.Bool("init-log", false, "Initialize log metadata in the database and exit")
	initLogForTest := flag.Bool("init-log-for-test", false, "For testing: initialize log metadata if not already initialized, then serve")

	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	if *grpcAddr != "" {
		c.MTCA.GRPCMTCA.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.MTCA.DebugAddr = *debugAddr
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(
		cmd.SyslogConfig{StdoutLevel: c.Syslog.StdoutLevel, SyslogLevel: c.Syslog.SyslogLevel},
		c.OpenTelemetry, c.MTCA.DebugAddr)
	defer oTelShutdown(context.Background())
	cmd.LogStartup(logger)

	slogger := cmd.NewSlogger(c.Syslog)

	metrics := mtca.NewMTCAMetrics(scope)

	tlsConfig, err := c.MTCA.TLS.Load(scope)
	cmd.FailOnError(err, "Loading TLS config")

	logID, err := c.MTCA.LogID.Load()
	cmd.FailOnError(err, "Parsing Log ID")

	profiles := make(map[string]*issuance.Profile)
	for name, profileConfig := range c.MTCA.Issuance.CertProfiles {
		if !profileConfig.MTC {
			cmd.Fail("MTCA configured with non-MTC profile")
		}
		profile, err := issuance.NewProfile(profileConfig)
		cmd.FailOnError(err, "Loading profile")
		profiles[name] = profile
	}

	clk := clock.New()
	var crlShards int
	issuers := make([]*issuance.Issuer, 0, len(c.MTCA.Issuance.Issuers))
	for i, issuerConfig := range c.MTCA.Issuance.Issuers {
		// Double check that all issuers have the same number of CRL shards, because
		// crl-updater relies upon that invariant.
		if issuerConfig.CRLShards != 0 && crlShards == 0 {
			crlShards = issuerConfig.CRLShards
		}
		if issuerConfig.CRLShards != crlShards {
			cmd.Fail(fmt.Sprintf("issuer %d has %d shards, want %d", i, issuerConfig.CRLShards, crlShards))
		}

		// Also check that all the profiles they list actually exist.
		for _, profile := range issuerConfig.Profiles {
			_, found := profiles[profile]
			if !found {
				cmd.Fail(fmt.Sprintf("issuer %d lists unrecognized profile %q", i, profile))
			}
		}

		issuer, err := issuance.LoadIssuer(issuerConfig, clk)
		cmd.FailOnError(err, fmt.Sprintf("Loading issuer %q", issuerConfig.Location.CertFile))
		issuers = append(issuers, issuer)
	}

	var activeIssuer *issuance.Issuer
	for _, iss := range issuers {
		if iss.IsActive() {
			if activeIssuer != nil {
				cmd.Fail("only one issuer may be active per MTCA (as specified by having a non-empty 'profiles' list)")
			}
			activeIssuer = iss
		}
	}
	if activeIssuer == nil {
		cmd.Fail("no issuers were marked active (as specified by having a non-empty 'profiles' list)")
	}

	dbMap, err := sa.InitDB(c.MTCA.DB, scope, logger)
	cmd.FailOnError(err, "While initializing dbMap")

	s3c, err := bs3.FromConfig(c.MTCA.S3, logger)
	cmd.FailOnError(err, "Loading S3 config")

	mtcaImpl, err := mtca.New(
		activeIssuer,
		profiles,
		logID,
		c.MTCA.SequencingPeriod.Duration,
		treedb.New(dbMap),
		s3c,
		slogger,
		metrics,
		clk)
	cmd.FailOnError(err, "Building MTCA")

	if *initLog && *initLogForTest {
		cmd.Fail("only one of -init-log and -init-log-for-test may happen")
	}
	if *initLog {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err = mtcaImpl.InitLog(ctx)
		cmd.FailOnError(err, "Initializing MTC issuance log")
		return
	}
	if *initLogForTest {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err = mtcaImpl.InitLog(ctx)
		if err != nil && !errors.Is(err, mtca.ErrIssuanceLogAlreadyInitialized) {
			cmd.FailOnError(err, "Initializing MTC issuance log for test")
		}
	}

	err = mtcaImpl.Preflight(context.Background())
	cmd.FailOnError(err, "Loading log state")

	caMetrics := ca.NewCAMetrics(scope)
	crli, err := ca.NewCRLImpl(
		issuers,
		c.MTCA.Issuance.CRLProfile,
		4000,
		logger,
		caMetrics,
	)
	cmd.FailOnError(err, "Failed to create CRL impl")

	srv := bgrpc.NewServer(c.MTCA.GRPCMTCA, logger).Add(
		&mtcapb.MTCA_ServiceDesc, mtcaImpl).Add(
		&capb.CRLGenerator_ServiceDesc, crli)

	start, err := srv.Build(tlsConfig, scope, clk)
	cmd.FailOnError(err, "Unable to setup MTCA gRPC server")

	// Cancel will be called after start() returns, which happens after GracefulStop() returns.
	// That means all inflight RPCs will be done, which means the last of the pool has been sequenced.
	// GracefulStop() is registered as part of srv.Build() above.
	ctx, cancel := context.WithCancel(context.Background())
	var loopWG sync.WaitGroup
	loopWG.Go(func() {
		mtcaImpl.Loop(ctx)
	})
	defer func() {
		cancel()
		loopWG.Wait()
	}()

	cmd.FailOnError(start(), "MTCA gRPC service failed")
}

func init() {
	cmd.RegisterCommand("boulder-mtca", main, &cmd.ConfigValidator{Config: &Config{}})
}
