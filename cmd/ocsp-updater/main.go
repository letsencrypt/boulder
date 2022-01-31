package notmain

import (
	"database/sql"
	"flag"
	"os"
	"strings"

	"github.com/honeycombio/beeline-go"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/ocsp_updater"
	ocsp_updater_config "github.com/letsencrypt/boulder/ocsp_updater/config"
	"github.com/letsencrypt/boulder/rocsp"
	rocsp_config "github.com/letsencrypt/boulder/rocsp/config"
	"github.com/letsencrypt/boulder/sa"
)

type Config struct {
	OCSPUpdater ocsp_updater_config.Config

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

	conf := c.OCSPUpdater
	err = features.Set(conf.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	bc, err := c.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

	stats, logger := cmd.StatsAndLogging(c.Syslog, conf.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	db, err := sa.InitSqlDb(conf.DB, stats)
	cmd.FailOnError(err, "Failed to initialize database client")

	var readOnlyDb *sql.DB
	readOnlyDbDSN, _ := conf.ReadOnlyDB.URL()
	if readOnlyDbDSN == "" {
		readOnlyDb = db
	} else {
		readOnlyDb, err = sa.InitSqlDb(conf.ReadOnlyDB, stats)
		cmd.FailOnError(err, "Failed to initialize read-only database client")
	}

	clk := cmd.Clock()

	redisConf := c.OCSPUpdater.Redis
	var rocspClient *rocsp.WritingClient
	if redisConf != nil {
		rocspClient, err = rocsp_config.MakeClient(redisConf, clk, stats)
		cmd.FailOnError(err, "making Redis client")
	}
	issuers, err := rocsp_config.LoadIssuers(c.OCSPUpdater.Issuers)
	cmd.FailOnError(err, "loading issuers")

	tlsConfig, err := c.OCSPUpdater.TLS.Load()
	cmd.FailOnError(err, "TLS config")
	clientMetrics := bgrpc.NewClientMetrics(stats)
	caConn, err := bgrpc.ClientSetup(c.OCSPUpdater.OCSPGeneratorService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to CA")
	ogc := capb.NewOCSPGeneratorClient(caConn)

	var serialSuffixes []string
	if c.OCSPUpdater.SerialSuffixShards != "" {
		serialSuffixes = strings.Fields(c.OCSPUpdater.SerialSuffixShards)
	}

	updater, err := ocsp_updater.New(
		stats,
		clk,
		db,
		readOnlyDb,
		rocspClient,
		issuers,
		serialSuffixes,
		ogc,
		// Necessary evil for now
		conf,
		logger,
	)
	cmd.FailOnError(err, "Failed to create updater")

	go cmd.CatchSignals(logger, nil)
	for {
		updater.Tick()
	}
}

func init() {
	cmd.RegisterCommand("ocsp-updater", main)
}
