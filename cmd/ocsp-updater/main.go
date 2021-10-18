package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
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

// failCounter provides a concurrent safe counter.
type failCounter struct {
	mu    sync.Mutex
	count int
}

func (c *failCounter) Add(i int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count += i
}

func (c *failCounter) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count = 0
}

func (c *failCounter) Value() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
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
	readFailures  failCounter

	serialSuffixes []string
	queryBody      string

	// Used to calculate how far back stale OCSP responses should be looked for
	ocspMinTimeToExpiry time.Duration
	// Maximum number of individual OCSP updates to attempt in parallel. Making
	// these requests in parallel allows us to get higher total throughput.
	parallelGenerateOCSPRequests int

	stalenessHistogram   prometheus.Histogram
	genStoreHistogram    prometheus.Histogram
	generatedCounter     *prometheus.CounterVec
	storedCounter        *prometheus.CounterVec
	markExpiredCounter   *prometheus.CounterVec
	findStaleOCSPCounter *prometheus.CounterVec
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
		Help: "A counter of OCSP response generation calls labeled by result",
	}, []string{"result"})
	stats.MustRegister(generatedCounter)
	storedCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ocsp_updater_stored",
		Help: "A counter of OCSP response storage calls labeled by result",
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
	markExpiredCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mark_expired",
		Help: "A counter of mark expired calls labeled by result",
	}, []string{"result"})
	stats.MustRegister(markExpiredCounter)
	findStaleOCSPCounter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "find_stale_ocsp",
		Help: "A counter of query for stale OCSP responses labeled by result",
	}, []string{"result"})
	stats.MustRegister(findStaleOCSPCounter)

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
		markExpiredCounter:           markExpiredCounter,
		findStaleOCSPCounter:         findStaleOCSPCounter,
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

// findStaleOCSPResponses sends a goroutine to fetch rows of stale OCSP
// responses from the database and returns results on a channel.
func (updater *OCSPUpdater) findStaleOCSPResponses(ctx context.Context, oldestLastUpdatedTime time.Time, batchSize int) <-chan core.CertificateStatus {
	// staleStatusesOut channel contains all stale ocsp responses that need
	// updating.
	staleStatusesOut := make(chan core.CertificateStatus)

	args := make([]interface{}, 0)
	args = append(args, oldestLastUpdatedTime)

	// If serialSuffixes is unset, this will be deliberately a no-op.
	for _, c := range updater.serialSuffixes {
		args = append(args, c)
	}
	args = append(args, batchSize)

	go func() {
		defer close(staleStatusesOut)

		rows, err := updater.readOnlyDb.Query(
			fmt.Sprintf(
				"SELECT %s FROM certificateStatus %s",
				strings.Join(sa.CertStatusMetadataFields(), ","),
				updater.queryBody,
			),
			args...,
		)

		// If error, log and increment retries for backoff. Else no
		// error, proceed to push statuses to channel.
		if err != nil {
			updater.log.AuditErrf("Failed to find stale OCSP responses: %s", err)
			updater.findStaleOCSPCounter.WithLabelValues("failed").Inc()
			updater.readFailures.Add(1)
			return
		}

		for rows.Next() {
			var status core.CertificateStatus
			err := sa.ScanCertStatusRow(rows, &status)
			if err != nil {
				rows.Close()
				updater.log.AuditErrf("Failed to find stale OCSP responses: %s", err)
				updater.findStaleOCSPCounter.WithLabelValues("failed").Inc()
				updater.readFailures.Add(1)
				return
			}
			staleness := oldestLastUpdatedTime.Sub(status.OCSPLastUpdated).Seconds()
			updater.stalenessHistogram.Observe(staleness)
			select {
			case <-ctx.Done():
				return
			case staleStatusesOut <- status:
			}
		}
		// Ensure the query wasn't interrupted before it could complete.
		err = rows.Close()
		if err != nil {
			updater.log.AuditErrf("Failed to find stale OCSP responses: %s", err)
			updater.findStaleOCSPCounter.WithLabelValues("failed").Inc()
			updater.readFailures.Add(1)
			return
		}

		updater.findStaleOCSPCounter.WithLabelValues("success").Inc()
		updater.readFailures.Reset()
	}()

	return staleStatusesOut
}

// generateResponse signs an new OCSP response for a given
// `core.CertificateStatus` entry.
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

// storeResponse stores a given CertificateStatus in the database.
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

// processExpired is a pipeline step to process a channel of
// `core.CertificateStatus` and set `isExpired` in the database.
func (updater *OCSPUpdater) processExpired(ctx context.Context, staleStatusesIn <-chan core.CertificateStatus) <-chan core.CertificateStatus {
	tickStart := updater.clk.Now()
	staleStatusesOut := make(chan core.CertificateStatus)
	go func() {
		defer close(staleStatusesOut)
		for status := range staleStatusesIn {
			if !status.IsExpired && tickStart.After(status.NotAfter) {
				err := updater.markExpired(status)
				if err != nil {
					// Update error counters and log
					updater.log.AuditErrf("Failed to set certificate expired: %s", err)
					updater.markExpiredCounter.WithLabelValues("failed").Inc()
				} else {
					updater.markExpiredCounter.WithLabelValues("success").Inc()
				}
			}
			select {
			case <-ctx.Done():
				return
			case staleStatusesOut <- status:
			}
		}
	}()

	return staleStatusesOut
}

// generateOCSPResponses is the final stage of a pipeline. It takes a
// channel of `core.CertificateStatus` and sends a goroutine for each to
// obtain a new OCSP response and update the status in the database.
func (updater *OCSPUpdater) generateOCSPResponses(ctx context.Context, staleStatusesIn <-chan core.CertificateStatus) {
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

	// Work runs as a goroutine per ocsp response to obtain a new ocsp
	// response and store it in the database.
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

	// Consume the stale statuses channel and send off a sign/store request
	// for each stale response.
	for status := range staleStatusesIn {
		wait()
		go work(status)
	}

	// Block until the sem channel reaches its full capacity again,
	// indicating each goroutine has completed.
	for i := 0; i < updater.parallelGenerateOCSPRequests; i++ {
		wait()
	}
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	oldestLastUpdatedTime := updater.clk.Now().Add(-updater.ocspMinTimeToExpiry)

	// Run pipeline
	updater.generateOCSPResponses(ctx, updater.processExpired(ctx, updater.findStaleOCSPResponses(ctx, oldestLastUpdatedTime, updater.batchSize)))

	end := updater.clk.Now()
	took := end.Sub(start)
	long, state := "false", "success"
	if took > updater.tickWindow {
		long = "true"
	}

	// Set sleep duration to the configured tickWindow.
	sleepDur := start.Add(updater.tickWindow).Sub(end)

	// Set sleep duration higher to backoff starting the next tick and
	// reading from the database if the last read failed.
	readFails := updater.readFailures.Value()
	if readFails > 0 {
		sleepDur = core.RetryBackoff(
			readFails,
			updater.tickWindow,
			updater.maxBackoff,
			updater.backoffFactor,
		)
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
