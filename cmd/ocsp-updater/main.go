package notmain

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/honeycombio/beeline-go"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/ocsp_updater"
	ocsp_updater_config "github.com/letsencrypt/boulder/ocsp_updater/config"
	"github.com/letsencrypt/boulder/sa"
)

type config struct {
	OCSPUpdater ocsp_updater_config.Config

	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig
}

func configureDb(dbConfig cmd.DBConfig) (*sql.DB, error) {
	dsn, err := dbConfig.URL()
	if err != nil {
		return nil, fmt.Errorf("while loading DSN from 'DBConnectFile': %s", err)
	}

	conf, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("while parsing DSN from 'DBConnectFile': %s", err)
	}

	// Transaction isolation level 'READ-UNCOMMITTED' trades consistency for
	// performance.
	if len(conf.Params) == 0 {
		conf.Params = map[string]string{
			"tx_isolation":      "'READ-UNCOMMITTED'",
			"interpolateParams": "true",
			"parseTime":         "true",
		}
	} else {
		conf.Params["tx_isolation"] = "'READ-UNCOMMITTED'"
		conf.Params["interpolateParams"] = "true"
		conf.Params["parseTime"] = "true"
	}

	db, err := sql.Open("mysql", conf.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("couldn't setup database client: %s", err)
	}

	db.SetMaxOpenConns(dbConfig.MaxOpenConns)
	db.SetMaxIdleConns(dbConfig.MaxIdleConns)
	db.SetConnMaxLifetime(dbConfig.ConnMaxLifetime.Duration)
	db.SetConnMaxIdleTime(dbConfig.ConnMaxIdleTime.Duration)
	return db, nil
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

	db, err := configureDb(conf.DB)
	cmd.FailOnError(err, "Failed to create database client")

	dbAddr, dbUser, err := conf.DB.DSNAddressAndUser()
	cmd.FailOnError(err, "Failed to parse DB config")

	sa.InitDBMetrics(db, stats, sa.NewDbSettingsFromDBConfig(conf.DB), dbAddr, dbUser)

	var readOnlyDb *sql.DB
	readOnlyDbDSN, _ := conf.ReadOnlyDB.URL()
	if readOnlyDbDSN == "" {
		readOnlyDb = db
	} else {
		readOnlyDb, err = configureDb(conf.ReadOnlyDB)
		cmd.FailOnError(err, "Failed to create read-only database client")

		dbAddr, dbUser, err := conf.ReadOnlyDB.DSNAddressAndUser()
		cmd.FailOnError(err, "Failed to parse read-only DB config")

		sa.InitDBMetrics(readOnlyDb, stats, sa.NewDbSettingsFromDBConfig(conf.DB), dbAddr, dbUser)
	}

	clk := cmd.Clock()

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
