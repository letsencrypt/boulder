package notmain

import (
	"database/sql"
	"flag"
	"os"
	"strings"
	"time"

	"github.com/honeycombio/beeline-go"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	ocsp_updater "github.com/letsencrypt/boulder/ocsp/updater"
	"github.com/letsencrypt/boulder/rocsp"
	rocsp_config "github.com/letsencrypt/boulder/rocsp/config"
	"github.com/letsencrypt/boulder/sa"
)

type Config struct {
	OCSPUpdater struct {
		cmd.ServiceConfig
		DB         cmd.DBConfig
		ReadOnlyDB cmd.DBConfig
		Redis      *rocsp_config.RedisConfig

		// Issuers is a map from filenames to short issuer IDs.
		// Each filename must contain an issuer certificate. The short issuer
		// IDs are arbitrarily assigned and must be consistent across OCSP
		// components. For production we'll use the number part of the CN, i.e.
		// E1 -> 1, R3 -> 3, etc.
		Issuers map[string]int

		OldOCSPWindow    cmd.ConfigDuration
		OldOCSPBatchSize int

		OCSPMinTimeToExpiry          cmd.ConfigDuration
		ParallelGenerateOCSPRequests int

		// TODO(#5933): Replace this with a unifed RetryBackoffConfig
		SignFailureBackoffFactor float64
		SignFailureBackoffMax    cmd.ConfigDuration

		SerialSuffixShards string

		OCSPGeneratorService *cmd.GRPCClientConfig

		Features map[string]bool
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
	var redisTimeout time.Duration
	if redisConf != nil {
		rocspClient, err = rocsp_config.MakeClient(redisConf, clk, stats)
		redisTimeout = redisConf.Timeout.Duration
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
		conf.OldOCSPBatchSize,
		conf.OldOCSPWindow.Duration,
		conf.SignFailureBackoffMax.Duration,
		conf.SignFailureBackoffFactor,
		conf.OCSPMinTimeToExpiry.Duration,
		conf.ParallelGenerateOCSPRequests,
		redisTimeout,
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
