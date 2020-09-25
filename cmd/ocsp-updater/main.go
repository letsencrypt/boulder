package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jmhodges/clock"
	akamaipb "github.com/letsencrypt/boulder/akamai/proto"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
	"github.com/prometheus/client_golang/prometheus"
)

/*
 * ocspDB is an interface collecting the gorp.DbMap functions that the
 * various parts of OCSPUpdater rely on. Using this adapter shim allows tests to
 * swap out the dbMap implementation.
 */
type ocspDB interface {
	Select(i interface{}, query string, args ...interface{}) ([]interface{}, error)
	SelectOne(holder interface{}, query string, args ...interface{}) error
	Exec(query string, args ...interface{}) (sql.Result, error)
}

// OCSPUpdater contains the useful objects for the Updater
type OCSPUpdater struct {
	log blog.Logger
	clk clock.Clock

	dbMap ocspDB

	ogc capb.OCSPGeneratorClient

	tickWindow    time.Duration
	batchSize     int
	tickHistogram *prometheus.HistogramVec

	maxBackoff    time.Duration
	backoffFactor float64
	tickFailures  int

	// Used to calculate how far back stale OCSP responses should be looked for
	ocspMinTimeToExpiry time.Duration
	// Maximum number of individual OCSP updates to attempt in parallel. Making
	// these requests in parallel allows us to get higher total throughput.
	parallelGenerateOCSPRequests int

	purgerService akamaipb.AkamaiPurgerClient
	// issuer is used to generate OCSP request URLs to purge
	issuer *x509.Certificate

	genStoreHistogram prometheus.Histogram
	generatedCounter  *prometheus.CounterVec
	storedCounter     *prometheus.CounterVec
}

func newUpdater(
	stats prometheus.Registerer,
	clk clock.Clock,
	dbMap ocspDB,
	ogc capb.OCSPGeneratorClient,
	apc akamaipb.AkamaiPurgerClient,
	config OCSPUpdaterConfig,
	issuerPath string,
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
		Name: "ocsp_updater_ticks",
		Help: "A histogram of ocsp-updater tick latencies labelled by result and whether the tick was considered longer than expected",
	}, []string{"result", "long"})
	stats.MustRegister(tickHistogram)

	updater := OCSPUpdater{
		clk:                          clk,
		dbMap:                        dbMap,
		ogc:                          ogc,
		log:                          log,
		ocspMinTimeToExpiry:          config.OCSPMinTimeToExpiry.Duration,
		parallelGenerateOCSPRequests: config.ParallelGenerateOCSPRequests,
		purgerService:                apc,
		genStoreHistogram:            genStoreHistogram,
		generatedCounter:             generatedCounter,
		storedCounter:                storedCounter,
		tickHistogram:                tickHistogram,
		tickWindow:                   config.OldOCSPWindow.Duration,
		batchSize:                    config.OldOCSPBatchSize,
		maxBackoff:                   config.SignFailureBackoffMax.Duration,
		backoffFactor:                config.SignFailureBackoffFactor,
	}

	if updater.purgerService != nil {
		issuer, err := core.LoadCert(issuerPath)
		if err != nil {
			return nil, err
		}
		updater.issuer = issuer
	}

	return &updater, nil
}

func (updater *OCSPUpdater) findStaleOCSPResponses(oldestLastUpdatedTime time.Time, batchSize int) ([]core.CertificateStatus, error) {
	statuses, err := sa.SelectCertificateStatuses(
		updater.dbMap,
		`WHERE ocspLastUpdated < :lastUpdate
		 AND NOT isExpired
		 ORDER BY ocspLastUpdated ASC
		 LIMIT :limit`,
		map[string]interface{}{
			"lastUpdate": oldestLastUpdatedTime,
			"limit":      batchSize,
		},
	)
	if db.IsNoRows(err) {
		return statuses, nil
	}
	return statuses, err
}

func getCertDER(selector ocspDB, serial string) ([]byte, error) {
	cert, err := sa.SelectCertificate(selector, serial)
	if err != nil {
		if db.IsNoRows(err) {
			cert, err = sa.SelectPrecertificate(selector, serial)
			// If there was still a non-nil error return it. If we can't find
			// a precert row something is amiss, we have a certificateStatus row with
			// no matching certificate or precertificate.
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return cert.DER, nil
}

func (updater *OCSPUpdater) generateResponse(ctx context.Context, status core.CertificateStatus) (*core.CertificateStatus, error) {
	ocspReq := capb.GenerateOCSPRequest{
		Reason:    int32(status.RevokedReason),
		Status:    string(status.Status),
		RevokedAt: status.RevokedDate.UnixNano(),
	}
	if status.IssuerID != nil && *status.IssuerID != 0 {
		ocspReq.Serial = status.Serial
		ocspReq.IssuerID = *status.IssuerID
	} else {
		certDER, err := getCertDER(updater.dbMap, status.Serial)
		if err != nil {
			return nil, err
		}
		ocspReq.CertDER = certDER
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
	_, err := updater.dbMap.Exec(
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
	_, err := updater.dbMap.Exec(
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

	Syslog cmd.SyslogConfig

	Common struct {
		IssuerCert string
	}
}

// OCSPUpdaterConfig provides the various window tick times and batch sizes needed
// for the OCSP (and SCT) updater
type OCSPUpdaterConfig struct {
	cmd.ServiceConfig
	cmd.DBConfig

	OldOCSPWindow    cmd.ConfigDuration
	OldOCSPBatchSize int

	OCSPMinTimeToExpiry          cmd.ConfigDuration
	ParallelGenerateOCSPRequests int

	AkamaiBaseURL           string
	AkamaiClientToken       string
	AkamaiClientSecret      string
	AkamaiAccessToken       string
	AkamaiV3Network         string
	AkamaiPurgeRetries      int
	AkamaiPurgeRetryBackoff cmd.ConfigDuration

	SignFailureBackoffFactor float64
	SignFailureBackoffMax    cmd.ConfigDuration

	SAService            *cmd.GRPCClientConfig
	OCSPGeneratorService *cmd.GRPCClientConfig
	AkamaiPurgerService  *cmd.GRPCClientConfig

	Features map[string]bool
}

func setupClients(c OCSPUpdaterConfig, stats prometheus.Registerer, clk clock.Clock) (
	capb.OCSPGeneratorClient,
	akamaipb.AkamaiPurgerClient,
) {
	var tls *tls.Config
	var err error
	if c.TLS.CertFile != nil {
		tls, err = c.TLS.Load()
		cmd.FailOnError(err, "TLS config")
	}
	clientMetrics := bgrpc.NewClientMetrics(stats)
	caConn, err := bgrpc.ClientSetup(c.OCSPGeneratorService, tls, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to CA")
	ogc := bgrpc.NewOCSPGeneratorClient(capb.NewOCSPGeneratorClient(caConn))

	var apc akamaipb.AkamaiPurgerClient
	if c.AkamaiPurgerService != nil {
		apcConn, err := bgrpc.ClientSetup(c.AkamaiPurgerService, tls, clientMetrics, clk)
		cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to Akamai Purger service")
		apc = akamaipb.NewAkamaiPurgerClient(apcConn)
	}

	return ogc, apc
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

	stats, logger := cmd.StatsAndLogging(c.Syslog, conf.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	// Configure DB
	dbURL, err := conf.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, conf.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Could not connect to database")

	// Collect and periodically report DB metrics using the DBMap and prometheus stats.
	sa.InitDBMetrics(dbMap, stats)

	clk := cmd.Clock()
	ogc, apc := setupClients(conf, stats, clk)

	updater, err := newUpdater(
		stats,
		clk,
		dbMap,
		ogc,
		apc,
		// Necessary evil for now
		conf,
		c.Common.IssuerCert,
		logger,
	)
	cmd.FailOnError(err, "Failed to create updater")

	go cmd.CatchSignals(logger, nil)

	for {
		updater.tick()
	}
}
