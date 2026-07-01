//go:build go1.27

package notmain

import (
	"context"
	"database/sql"
	"flag"
	"log/slog"
	"os"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/borp"
	"github.com/letsencrypt/boulder/blog"
	"github.com/letsencrypt/boulder/cmd"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
	mtca "github.com/letsencrypt/boulder/mtca"
	mtcapb "github.com/letsencrypt/boulder/mtca/proto"
)

type Config struct {
	MTCA struct {
		cmd.ServiceConfig

		GRPCMTCA *cmd.GRPCServerConfig

		DB cmd.DBConfig

		// Issuer holds the configuration for a single MTCA instance with a single mtcaID.
		// We run a separate process for each issuer.
		// TODO: the issuance package parses the CA certificate as a self-signed X.509
		// certificate, but per MTC draft, a CA SHOULD be represented by an RFC 9925
		// unsigned certificate: https://www.rfc-editor.org/rfc/rfc9925.html.
		Issuer issuance.IssuerConfig
	}

	Syslog        blog.Config
	OpenTelemetry cmd.OpenTelemetryConfig
}

func main() {
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	initLog := flag.Bool("init-log", false, "Initialize log metadata in the database and exit")
	initLogForTest := flag.Bool("init-log-for-test", false, "For testing: initialize log metadata (ignoring errors), then serve")

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

	issuer, err := issuance.LoadIssuer(c.MTCA.Issuer, clk)
	cmd.FailOnError(err, "Loading issuer")

	url, err := c.MTCA.DB.URL()
	cmd.FailOnError(err, "Reading DB URL")
	db, err := sql.Open("mysql", url)
	cmd.FailOnError(err, "Opening DB")
	dbMap := &borp.DbMap{Db: db, Dialect: borp.MySQLDialect{}}

	mtcaImpl := mtca.New(issuer, dbMap, logger)

	if *initLog {
		err = mtcaImpl.InitLog(context.Background())
		cmd.FailOnError(err, "Initializing log")
		return
	}
	if *initLogForTest {
		err = mtcaImpl.InitLog(context.Background())
		if err != nil {
			logger.Info(context.Background(),
				"Non-fatal error initializing MTC log DB for test",
				slog.String("info", err.Error()))
		}
	}

	srv := bgrpc.NewServer(c.MTCA.GRPCMTCA, logger).Add(
		&mtcapb.MTCA_ServiceDesc, mtcaImpl)

	start, err := srv.Build(tlsConfig, scope, clk)
	cmd.FailOnError(err, "Unable to setup MTCA gRPC server")

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel will be called after start() returns, which happens after GracefulStop() returns.
	// That means all inflight RPCs will be done, which means the last of the pool has been sequenced.
	defer cancel()
	go mtcaImpl.Loop(ctx)

	cmd.FailOnError(start(), "MTCA gRPC service failed")
}

func init() {
	cmd.RegisterCommand("boulder-mtca", main, &cmd.ConfigValidator{Config: &Config{}})
}
