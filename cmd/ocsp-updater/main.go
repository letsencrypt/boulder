package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/honeycombio/beeline-go"
	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

// ocspDB and ocspReadOnlyDB are interfaces collecting the `sql.DB` methods that
// the various parts of OCSPUpdater rely on. Using this adapter shim allows tests to
// swap out the `sql.DB` implementation.

// ocspReadOnlyDb provides only read-only portions of the `sql.DB` interface.
type ocspReadOnlyDb interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
}

// ocspDb provides read-write portions of the `sql.DB` interface.
type ocspDb interface {
	ocspReadOnlyDb
	Exec(query string, args ...interface{}) (sql.Result, error)
}

// OCSPUpdater contains the useful objects for the Updater
type OCSPUpdater struct {
	log blog.Logger
	clk clock.Clock

	db         ocspDb
	readOnlyDb ocspReadOnlyDb

	ogc capb.OCSPGeneratorClient

	tickWindow    time.Duration
	batchSize     int
	tickHistogram *prometheus.HistogramVec

	maxBackoff    time.Duration
	backoffFactor float64
	tickFailures  int

	serialSuffixes []string
	queryBody      string

	// Used to calculate how far back stale OCSP responses should be looked for
	ocspMinTimeToExpiry time.Duration
	// Maximum number of individual OCSP updates to attempt in parallel. Making
	// these requests in parallel allows us to get higher total throughput.
	parallelGenerateOCSPRequests int

	stalenessHistogram prometheus.Histogram
	genStoreHistogram  prometheus.Histogram
	generatedCounter   *prometheus.CounterVec
	storedCounter      *prometheus.CounterVec
}

func newUpdater(
	stats prometheus.Registerer,
	clk clock.Clock,
	db ocspDb,
	readOnlyDb ocspReadOnlyDb,
	serialSuffixes []string,
	ogc capb.OCSPGeneratorClient,
	config OCSPUpdaterConfig,
	log blog.Logger,
) (*OCSPUpdater, error) {
	if config.OldOCSPBatchSize == 0 {
		return nil, fmt.Errorf("Loop batch sizes must be non-zero")
	}
	if config.OldOCSPWindow.Duration == 0 {
		return nil, fmt.Errorf("Loop window sizes must be non-zero")
	}
	if config.ParallelGenerateOCSPRequests == 0 {
		// Default to 1
		config.ParallelGenerateOCSPRequests = 1
	}
	for _, s := range serialSuffixes {
		if len(s) != 1 || strings.ToLower(s) != s {
			return nil, fmt.Errorf("serial suffixes must all be one lowercase character, got %q, expected %q", s, strings.ToLower(s))
		}
		c := s[0]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, errors.New("valid range for suffixes is [0-9a-f]")
		}
	}

	var queryBody strings.Builder
	queryBody.WriteString("WHERE ocspLastUpdated < ? AND NOT isExpired ")
	if len(serialSuffixes) > 0 {
		fmt.Fprintf(&queryBody, "AND RIGHT(serial, 1) IN ( %s ) ",
			getQuestionsForShardList(len(serialSuffixes)),
		)
	}
	queryBody.WriteString("ORDER BY ocspLastUpdated ASC LIMIT ?")

	genStoreHistogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "ocsp_updater_generate_and_store",
		Help: "A histogram of latencies of OCSP generation and storage latencies",
	})
	stats.MustRegister(genStoreHistogram)
	generatedCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ocsp_updater_generated",
		Help: "A counter of OCSP response generation calls labelled by result",
	}, []string{"result"})
	stats.MustRegister(generatedCounter)
	storedCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ocsp_updater_stored",
		Help: "A counter of OCSP response storage calls labelled by result",
	}, []string{"result"})
	stats.MustRegister(storedCounter)
	tickHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ocsp_updater_ticks",
		Help:    "A histogram of ocsp-updater tick latencies labelled by result and whether the tick was considered longer than expected",
		Buckets: []float64{0.01, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000},
	}, []string{"result", "long"})
	stats.MustRegister(tickHistogram)
	stalenessHistogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "ocsp_status_staleness",
		Help:    "How long past the refresh time a status is when we try to refresh it. Will always be > 0, but must stay well below 12 hours.",
		Buckets: []float64{10, 100, 1000, 10000, 21600, 32400, 36000, 39600, 43200, 54000, 64800, 75600, 86400, 108000, 129600, 172800},
	})
	stats.MustRegister(stalenessHistogram)

	updater := OCSPUpdater{
		clk:                          clk,
		db:                           db,
		readOnlyDb:                   readOnlyDb,
		ogc:                          ogc,
		log:                          log,
		ocspMinTimeToExpiry:          config.OCSPMinTimeToExpiry.Duration,
		parallelGenerateOCSPRequests: config.ParallelGenerateOCSPRequests,
		genStoreHistogram:            genStoreHistogram,
		generatedCounter:             generatedCounter,
		storedCounter:                storedCounter,
		stalenessHistogram:           stalenessHistogram,
		tickHistogram:                tickHistogram,
		tickWindow:                   config.OldOCSPWindow.Duration,
		batchSize:                    config.OldOCSPBatchSize,
		maxBackoff:                   config.SignFailureBackoffMax.Duration,
		backoffFactor:                config.SignFailureBackoffFactor,
		serialSuffixes:               serialSuffixes,
		queryBody:                    queryBody.String(),
	}

	return &updater, nil
}

func getQuestionsForShardList(count int) string {
	return strings.TrimRight(strings.Repeat("?,", count), ",")
}

func (updater *OCSPUpdater) findStaleOCSPResponses(oldestLastUpdatedTime time.Time, batchSize int) ([]core.CertificateStatus, error) {
	args := make([]interface{}, 0)
	args = append(args, oldestLastUpdatedTime)

	// If serialSuffixes is unset, this will be deliberately a no-op.
	for _, c := range updater.serialSuffixes {
		args = append(args, c)
	}
	args = append(args, batchSize)

	rows, err := updater.readOnlyDb.Query(
		fmt.Sprintf(
			"SELECT %s FROM certificateStatus %s",
			strings.Join(sa.CertStatusMetadataFields(), ","),
			updater.queryBody,
		),
		args...,
	)
	if err != nil {
		return nil, err
	}

	var statuses []core.CertificateStatus
	for rows.Next() {
		var status core.CertificateStatus
		err := sa.ScanCertStatusRow(rows, &status)
		if err != nil {
			rows.Close()
			return nil, err
		}
		statuses = append(statuses, status)

		updater.stalenessHistogram.Observe(
			oldestLastUpdatedTime.Sub(status.OCSPLastUpdated).Seconds(),
		)
	}
	// Ensure the query wasn't interrupted before it could complete.
	err = rows.Close()
	if err != nil {
		return nil, err
	}

	return statuses, err
}

func (updater *OCSPUpdater) generateResponse(ctx context.Context, status core.CertificateStatus) (*core.CertificateStatus, error) {
	if status.IssuerID == 0 {
		return nil, errors.New("cert status has 0 IssuerID")
	}
	ocspReq := capb.GenerateOCSPRequest{
		Serial:    status.Serial,
		IssuerID:  status.IssuerID,
		Status:    string(status.Status),
		Reason:    int32(status.RevokedReason),
		RevokedAt: status.RevokedDate.UnixNano(),
	}

	ocspResponse, err := updater.ogc.GenerateOCSP(ctx, &ocspReq)
	if err != nil {
		return nil, err
	}

	status.OCSPLastUpdated = updater.clk.Now()
	status.OCSPResponse = ocspResponse.Response

	return &status, nil
}

func (updater *OCSPUpdater) storeResponse(status *core.CertificateStatus) error {
	// Update the certificateStatus table with the new OCSP response, the status
	// WHERE is used make sure we don't overwrite a revoked response with a one
	// containing a 'good' status.
	_, err := updater.db.Exec(
		`UPDATE certificateStatus
		 SET ocspResponse=?,ocspLastUpdated=?
		 WHERE serial=?
		 AND status=?`,
		status.OCSPResponse,
		status.OCSPLastUpdated,
		status.Serial,
		string(status.Status),
	)
	return err
}

// markExpired updates a given CertificateStatus to have `isExpired` set.
func (updater *OCSPUpdater) markExpired(status core.CertificateStatus) error {
	_, err := updater.db.Exec(
		`UPDATE certificateStatus
 		SET isExpired = TRUE
 		WHERE serial = ?`,
		status.Serial,
	)
	return err
}

func (updater *OCSPUpdater) generateOCSPResponses(ctx context.Context, statuses []core.CertificateStatus) error {
	// Use the semaphore pattern from
	// https://github.com/golang/go/wiki/BoundingResourceUse to send a number of
	// GenerateOCSP / storeResponse requests in parallel, while limiting the total number of
	// outstanding requests. The number of outstanding requests equals the
	// capacity of the channel.
	sem := make(chan int, updater.parallelGenerateOCSPRequests)
	wait := func() {
		sem <- 1 // Block until there's capacity.
	}
	done := func(start time.Time) {
		<-sem // Indicate there's more capacity.
		updater.genStoreHistogram.Observe(time.Since(start).Seconds())
	}

	work := func(status core.CertificateStatus) {
		defer done(updater.clk.Now())
		meta, err := updater.generateResponse(ctx, status)
		if err != nil {
			updater.log.AuditErrf("Failed to generate OCSP response: %s", err)
			updater.generatedCounter.WithLabelValues("failed").Inc()
			return
		}
		updater.generatedCounter.WithLabelValues("success").Inc()
		err = updater.storeResponse(meta)
		if err != nil {
			updater.log.AuditErrf("Failed to store OCSP response: %s", err)
			updater.storedCounter.WithLabelValues("failed").Inc()
			return
		}
		updater.storedCounter.WithLabelValues("success").Inc()
	}

	for _, status := range statuses {
		wait()
		go work(status)
	}
	// Block until the channel reaches its full capacity again, indicating each
	// goroutine has completed.
	for i := 0; i < updater.parallelGenerateOCSPRequests; i++ {
		wait()
	}
	return nil
}

// updateOCSPResponses looks for certificates with stale OCSP responses and
// generates/stores new ones
func (updater *OCSPUpdater) updateOCSPResponses(ctx context.Context, batchSize int) error {
	tickStart := updater.clk.Now()
	statuses, err := updater.findStaleOCSPResponses(tickStart.Add(-updater.ocspMinTimeToExpiry), batchSize)
	if err != nil {
		updater.log.AuditErrf("Failed to find stale OCSP responses: %s", err)
		return err
	}

	for _, s := range statuses {
		if !s.IsExpired && tickStart.After(s.NotAfter) {
			err := updater.markExpired(s)
			if err != nil {
				return err
			}
		}
	}

	return updater.generateOCSPResponses(ctx, statuses)
}

type config struct {
	OCSPUpdater OCSPUpdaterConfig

	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig
}

// OCSPUpdaterConfig provides the various window tick times and batch sizes needed
// for the OCSP (and SCT) updater
type OCSPUpdaterConfig struct {
	cmd.ServiceConfig
	DB         cmd.DBConfig
	ReadOnlyDB cmd.DBConfig

	OldOCSPWindow    cmd.ConfigDuration
	OldOCSPBatchSize int

	OCSPMinTimeToExpiry          cmd.ConfigDuration
	ParallelGenerateOCSPRequests int

	SignFailureBackoffFactor float64
	SignFailureBackoffMax    cmd.ConfigDuration

	SerialSuffixShards string

	OCSPGeneratorService *cmd.GRPCClientConfig

	Features map[string]bool
}

func (updater *OCSPUpdater) tick() {
	start := updater.clk.Now()
	err := updater.updateOCSPResponses(context.Background(), updater.batchSize)
	end := updater.clk.Now()
	took := end.Sub(start)
	long, state := "false", "success"
	if took > updater.tickWindow {
		long = "true"
	}
	sleepDur := start.Add(updater.tickWindow).Sub(end)
	if err != nil {
		state = "failed"
		updater.tickFailures++
		sleepDur = core.RetryBackoff(
			updater.tickFailures,
			updater.tickWindow,
			updater.maxBackoff,
			updater.backoffFactor,
		)
	} else if updater.tickFailures > 0 {
		updater.tickFailures = 0
	}
	updater.tickHistogram.WithLabelValues(state, long).Observe(took.Seconds())
	updater.clk.Sleep(sleepDur)
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

	updater, err := newUpdater(
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
		updater.tick()
	}
}
