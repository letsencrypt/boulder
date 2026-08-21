//go:build go1.27

package notmain

import (
	"context"
	"crypto/mldsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/borp"

	"github.com/letsencrypt/boulder/bs3"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
	mtca "github.com/letsencrypt/boulder/mtca"
	mtcapb "github.com/letsencrypt/boulder/mtca/proto"
	"github.com/letsencrypt/boulder/trees/issuancelog"
)

type Config struct {
	MTCA struct {
		cmd.ServiceConfig

		GRPCMTCA *cmd.GRPCServerConfig

		DB cmd.DBConfig `validate:"required"`
		S3 bs3.Config   `validate:"required"`

		// LogID identifies the issuance log this MTCA sequences. Its CA ID must
		// match the issuer certificate's.
		LogID issuancelog.ID `validate:"required"`

		Issuance struct {
			CertProfiles map[string]issuance.ProfileConfig `validate:"required,dive,keys,alphanum,min=1,max=32,endkeys"`
			// Issuers holds the configuration for a single MTCA instance with a single CA ID.
			// We run a separate process for each issuer.
			// TODO: the issuance package parses the CA certificate as a self-signed X.509
			// certificate, but per MTC draft, a CA SHOULD be represented by an RFC 9925
			// unsigned certificate: https://www.rfc-editor.org/rfc/rfc9925.html.
			Issuers []issuance.IssuerConfig `validate:"min=1,max=1,dive"`
		}

		// SequencingPeriod controls how frequently the MTCA sequences a batch and signs a checkpoint.
		SequencingPeriod config.Duration `validate:"required"`

		// Mirror identifies the mirror whose cosignatures must be verified
		// before the MTCA serves them as part of a checkpoint.
		Mirror cmd.MirrorConfig `validate:"required"`
	}

	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig
}

// loadMLDSAPublicKey reads a PEM-encoded PKIX ML-DSA-44 public key.
func loadMLDSAPublicKey(filename string) (*mldsa.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("no PUBLIC KEY PEM block in %s", filename)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pubKey, ok := parsed.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is %T, must be ML-DSA-44", filename, parsed)
	}
	return pubKey, nil
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

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.MTCA.DebugAddr)
	defer oTelShutdown(context.Background())
	cmd.LogStartup(logger)

	tlsConfig, err := c.MTCA.TLS.Load(scope)
	cmd.FailOnError(err, "Loading TLS config")

	clk := clock.New()

	if len(c.MTCA.Issuance.Issuers) > 1 {
		cmd.Fail("multiple issuers in one MTCA process not supported")
	}
	issuer, err := issuance.LoadIssuer(c.MTCA.Issuance.Issuers[0], clk)
	cmd.FailOnError(err, "Loading issuer")

	profiles := make(map[string]*issuance.Profile)
	for name, profileConfig := range c.MTCA.Issuance.CertProfiles {
		if !profileConfig.MTC {
			cmd.Fail("MTCA configured with non-MTC profile")
		}
		profile, err := issuance.NewProfile(profileConfig)
		cmd.FailOnError(err, "Loading profile")
		profiles[name] = profile
	}

	url, err := c.MTCA.DB.URL()
	cmd.FailOnError(err, "Reading DB URL")
	db, err := sql.Open("mysql", url)
	cmd.FailOnError(err, "Opening DB")
	dbMap := &borp.DbMap{Db: db, Dialect: borp.MySQLDialect{}}

	s3c, err := bs3.FromConfig(c.MTCA.S3, logger)
	cmd.FailOnError(err, "Loading S3 config")

	mirrorPublicKey, err := loadMLDSAPublicKey(c.MTCA.Mirror.PublicKeyFile)
	cmd.FailOnError(err, "Loading mirror public key")

	mtcaImpl, err := mtca.New(
		issuer,
		profiles,
		c.MTCA.LogID,
		c.MTCA.SequencingPeriod.Duration,
		dbMap,
		s3c,
		c.MTCA.Mirror.ID,
		mirrorPublicKey,
		logger,
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

	srv := bgrpc.NewServer(c.MTCA.GRPCMTCA, logger).Add(
		&mtcapb.MTCA_ServiceDesc, mtcaImpl)

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
