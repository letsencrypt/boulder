package notmain

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jmhodges/clock"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/metrics"
	rocsp_config "github.com/letsencrypt/boulder/rocsp/config"
	"github.com/prometheus/client_golang/prometheus"
)

type config struct {
	ROCSPTool struct {
		Redis rocsp_config.RedisConfig
		// Issuers is a map from filenames to short issuer IDs.
		// Each filename must contain an issuer certificate. The short issuer
		// IDs are arbitrarily assigned and must be consistent across OCSP
		// components. For production we'll use the number part of the CN, i.e.
		// E1 -> 1, R3 -> 3, etc.
		Issuers map[string]int

		// If using load-from-db, this provides credentials to connect to the DB
		// and the CA. Otherwise, it's optional.
		LoadFromDB *LoadFromDBConfig
	}
}

// LoadFromDBConfig provides the credentials and configuration needed to load
// data from the certificateStatuses table in the DB and get it signed.
type LoadFromDBConfig struct {
	// Credentials to connect to the DB.
	DB cmd.DBConfig
	// Credentials to request OCSP signatures from the CA.
	GRPCTLS cmd.TLSConfig
	// Timeouts and hostnames for the CA.
	OCSPGeneratorService cmd.GRPCClientConfig
	// How fast to process rows.
	Speed ProcessingSpeed
}

type ProcessingSpeed struct {
	// If using load-from-db, this limits how many items per second we
	// scan from the DB. We might go slower than this depending on how fast
	// we read rows from the DB, but we won't go faster. Defaults to 2000.
	RowsPerSecond int
	// If using load-from-db, this controls how many parallel requests to
	// boulder-ca for OCSP signing we can make. Defaults to 100.
	ParallelSigns int
	// If using load-from-db, the LIMIT on our scanning queries. We have to
	// apply a limit because MariaDB will cut off our response at some
	// threshold of total bytes transferred (1 GB by default). Defaults to 10000.
	ScanBatchSize int
}

func init() {
	cmd.RegisterCommand("rocsp-tool", main)
}

func main() {
	if err := main2(); err != nil {
		log.Fatal(err)
	}
}

func main2() error {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	rand.Seed(time.Now().UnixNano())

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	if err != nil {
		return fmt.Errorf("reading JSON config file: %w", err)
	}

	issuers, err := loadIssuers(c.ROCSPTool.Issuers)
	if err != nil {
		return fmt.Errorf("loading issuers: %w", err)
	}
	if len(issuers) == 0 {
		return fmt.Errorf("'issuers' section of config JSON is required.")
	}
	clk := cmd.Clock()
	redisClient, err := rocsp_config.MakeClient(&c.ROCSPTool.Redis, clk)
	if err != nil {
		return fmt.Errorf("making client: %w", err)
	}

	var db *sql.DB
	var ocspGenerator capb.OCSPGeneratorClient
	var scanBatchSize int
	if c.ROCSPTool.LoadFromDB != nil {
		lfd := c.ROCSPTool.LoadFromDB
		db, err = configureDb(&lfd.DB)
		if err != nil {
			return fmt.Errorf("connecting to DB: %w", err)
		}

		ocspGenerator, err = configureOCSPGenerator(lfd.GRPCTLS,
			lfd.OCSPGeneratorService, clk, metrics.NoopRegisterer)
		if err != nil {
			return fmt.Errorf("configuring gRPC to CA: %w", err)
		}
		setDefault(&lfd.Speed.RowsPerSecond, 2000)
		setDefault(&lfd.Speed.ParallelSigns, 100)
		setDefault(&lfd.Speed.ScanBatchSize, 10000)
		scanBatchSize = lfd.Speed.ScanBatchSize
	}

	if len(flag.Args()) < 1 {
		helpExit()
	}

	ctx := context.Background()
	cl := client{
		issuers:       issuers,
		redis:         redisClient,
		db:            db,
		ocspGenerator: ocspGenerator,
		clk:           clk,
		scanBatchSize: scanBatchSize,
	}
	switch flag.Arg(0) {
	case "store":
		err := cl.storeResponsesFromFiles(ctx, flag.Args()[1:])
		if err != nil {
			return err
		}
	case "load-from-db":
		if c.ROCSPTool.LoadFromDB == nil {
			return fmt.Errorf("config field LoadFromDB was missing")
		}
		err = cl.loadFromDB(ctx, c.ROCSPTool.LoadFromDB.Speed)
		if err != nil {
			return fmt.Errorf("loading OCSP responses from DB: %w", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unrecognized subcommand %q\n", flag.Arg(0))
		helpExit()
	}
	return nil
}

func helpExit() {
	fmt.Fprintf(os.Stderr, "Usage: %s [store|copy-from-db] --config path/to/config.json\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "  store -- for each command line arg, read that filename as an OCSP response and store it in Redis")
	fmt.Fprintln(os.Stderr, "  load-from-db -- scan the database for all OCSP entries for unexpired certificates, and store in Redis")
	fmt.Fprintln(os.Stderr)
	flag.PrintDefaults()
	os.Exit(1)
}

func configureOCSPGenerator(tlsConf cmd.TLSConfig, grpcConf cmd.GRPCClientConfig, clk clock.Clock, stats prometheus.Registerer) (capb.OCSPGeneratorClient, error) {
	tlsConfig, err := tlsConf.Load()
	if err != nil {
		return nil, fmt.Errorf("loading TLS config: %w", err)
	}
	clientMetrics := bgrpc.NewClientMetrics(stats)
	caConn, err := bgrpc.ClientSetup(&grpcConf, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to CA")
	return capb.NewOCSPGeneratorClient(caConn), nil
}

func configureDb(dbConfig *cmd.DBConfig) (*sql.DB, error) {
	if dbConfig == nil {
		return nil, nil
	}
	dsn, err := dbConfig.URL()
	if err != nil {
		return nil, fmt.Errorf("loading DB URL: %w", err)
	}

	conf, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("while parsing DSN from 'DBConnectFile': %s", err)
	}

	if len(conf.Params) == 0 {
		conf.Params = make(map[string]string)
	}
	conf.Params["tx_isolation"] = "'READ-UNCOMMITTED'"
	conf.Params["interpolateParams"] = "true"
	conf.Params["parseTime"] = "true"

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

// setDefault sets the target to a default value, if it is zero.
func setDefault(target *int, def int) {
	if *target == 0 {
		*target = def
	}
}
