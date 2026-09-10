//go:build go1.27

package notmain

import (
	"context"
	"database/sql"
	"flag"
	"os"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/borp"

	"github.com/letsencrypt/boulder/bs3"
	"github.com/letsencrypt/boulder/cmd"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/mtcb"
	mtcbpb "github.com/letsencrypt/boulder/mtcb/proto"
)

type Config struct {
	MTCB struct {
		cmd.ServiceConfig

		GRPCMTCB *cmd.GRPCServerConfig

		DB cmd.DBConfig `validate:"required"`
		S3 bs3.Config   `validate:"required"`

		IssuerCerts []string `validate:"min=1,dive,required"`
	}

	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig
}

func main() {
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	configFile := flag.String("config", "", "File path to the configuration file for this service")

	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	if *grpcAddr != "" {
		c.MTCB.GRPCMTCB.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.MTCB.DebugAddr = *debugAddr
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.MTCB.DebugAddr)
	defer oTelShutdown(context.Background())
	cmd.LogStartup(logger)

	tlsConfig, err := c.MTCB.TLS.Load(scope)
	cmd.FailOnError(err, "Loading TLS config")

	clk := clock.New()

	var issuers []*issuance.Certificate
	for _, issuerPath := range c.MTCB.IssuerCerts {
		issuer, err := issuance.LoadCertificate(issuerPath)
		cmd.FailOnError(err, "Loading issuers")
		issuers = append(issuers, issuer)
	}

	url, err := c.MTCB.DB.URL()
	cmd.FailOnError(err, "Reading DB URL")
	db, err := sql.Open("mysql", url)
	cmd.FailOnError(err, "Opening DB")
	dbMap := &borp.DbMap{Db: db, Dialect: borp.MySQLDialect{}}

	s3c, err := bs3.FromConfig(c.MTCB.S3, logger)
	cmd.FailOnError(err, "Loading S3 config")

	mtcbImpl, err := mtcb.New(issuers, dbMap, s3c, logger, clk)
	cmd.FailOnError(err, "Building MTCB")

	srv := bgrpc.NewServer(c.MTCB.GRPCMTCB, logger).Add(
		&mtcbpb.MTCB_ServiceDesc, mtcbImpl)

	start, err := srv.Build(tlsConfig, scope, clk)
	cmd.FailOnError(err, "Unable to setup MTCB gRPC server")

	cmd.FailOnError(start(), "MTCB gRPC service failed")
}

func init() {
	cmd.RegisterCommand("boulder-mtcb", main, &cmd.ConfigValidator{Config: &Config{}})
}
