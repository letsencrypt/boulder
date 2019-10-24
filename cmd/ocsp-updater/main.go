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
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
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
	stats metrics.Scope
	log   blog.Logger
	clk   clock.Clock

	dbMap ocspDB

	cac core.CertificateAuthority
	sac core.StorageAuthority

	// Used to calculate how far back stale OCSP responses should be looked for
	ocspMinTimeToExpiry time.Duration
	// Used to calculate how far back in time the findStaleOCSPResponse will look
	ocspStaleMaxAge time.Duration
	// Maximum number of individual OCSP updates to attempt in parallel. Making
	// these requests in parallel allows us to get higher total throughput.
	parallelGenerateOCSPRequests int

	loops []*looper

	purgerService akamaipb.AkamaiPurgerClient
	// issuer is used to generate OCSP request URLs to purge
	issuer *x509.Certificate
}

func newUpdater(
	stats metrics.Scope,
	clk clock.Clock,
	dbMap ocspDB,
	ca core.CertificateAuthority,
	sac core.StorageAuthority,
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
	if config.OCSPStaleMaxAge.Duration == 0 {
		// Default to 30 days
		config.OCSPStaleMaxAge = cmd.ConfigDuration{Duration: time.Hour * 24 * 30}
	}
	if config.ParallelGenerateOCSPRequests == 0 {
		// Default to 1
		config.ParallelGenerateOCSPRequests = 1
	}

	updater := OCSPUpdater{
		stats:                        stats,
		clk:                          clk,
		dbMap:                        dbMap,
		cac:                          ca,
		log:                          log,
		sac:                          sac,
		ocspMinTimeToExpiry:          config.OCSPMinTimeToExpiry.Duration,
		ocspStaleMaxAge:              config.OCSPStaleMaxAge.Duration,
		parallelGenerateOCSPRequests: config.ParallelGenerateOCSPRequests,
		purgerService:                apc,
	}

	if updater.purgerService != nil {
		issuer, err := core.LoadCert(issuerPath)
		if err != nil {
			return nil, err
		}
		updater.issuer = issuer
	}

	// Setup loops
	updater.loops = []*looper{
		{
			clk:                  clk,
			stats:                stats.NewScope("OldOCSPResponses"),
			batchSize:            config.OldOCSPBatchSize,
			tickDur:              config.OldOCSPWindow.Duration,
			tickFunc:             updater.oldOCSPResponsesTick,
			name:                 "OldOCSPResponses",
			failureBackoffFactor: config.SignFailureBackoffFactor,
			failureBackoffMax:    config.SignFailureBackoffMax.Duration,
		},
	}

	return &updater, nil
}

func (updater *OCSPUpdater) findStaleOCSPResponses(oldestLastUpdatedTime time.Time, batchSize int) ([]core.CertificateStatus, error) {
	var statuses []core.CertificateStatus
	now := updater.clk.Now()
	maxAgeCutoff := now.Add(-updater.ocspStaleMaxAge)

	_, err := updater.dbMap.Select(
		&statuses,
		`SELECT
				cs.serial,
				cs.status,
				cs.revokedDate,
				cs.notAfter
				FROM certificateStatus AS cs
				WHERE cs.ocspLastUpdated > :maxAge
				AND cs.ocspLastUpdated < :lastUpdate
				AND NOT cs.isExpired
				ORDER BY cs.ocspLastUpdated ASC
				LIMIT :limit`,
		map[string]interface{}{
			"lastUpdate": oldestLastUpdatedTime,
			"maxAge":     maxAgeCutoff,
			"limit":      batchSize,
		},
	)
	if err == sql.ErrNoRows {
		return statuses, nil
	}
	return statuses, err
}

func (updater *OCSPUpdater) generateResponse(ctx context.Context, status core.CertificateStatus) (*core.CertificateStatus, error) {
	cert, err := sa.SelectCertificate(
		updater.dbMap,
		"WHERE serial = ?",
		status.Serial,
	)
	if err != nil {
		// If PrecertificateOCSP is enabled and the error indicates there was no
		// certificates table row then try to find a precertificate table row before
		// giving up with an error.
		if features.Enabled(features.PrecertificateOCSP) && err == sql.ErrNoRows {
			cert, err = sa.SelectPrecertificate(updater.dbMap, status.Serial)
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

	signRequest := core.OCSPSigningRequest{
		CertDER:   cert.DER,
		Reason:    status.RevokedReason,
		Status:    string(status.Status),
		RevokedAt: status.RevokedDate,
	}

	ocspResponse, err := updater.cac.GenerateOCSP(ctx, signRequest)
	if err != nil {
		return nil, err
	}

	status.OCSPLastUpdated = updater.clk.Now()
	status.OCSPResponse = ocspResponse

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

func (updater *OCSPUpdater) generateOCSPResponses(ctx context.Context, statuses []core.CertificateStatus, stats metrics.Scope) error {
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
		stats.TimingDuration("GenerateAndStore", time.Since(start))
	}

	work := func(status core.CertificateStatus) {
		defer done(updater.clk.Now())
		meta, err := updater.generateResponse(ctx, status)
		if err != nil {
			updater.log.AuditErrf("Failed to generate OCSP response: %s", err)
			stats.Inc("Errors.ResponseGeneration", 1)
			return
		}
		stats.Inc("GeneratedResponses", 1)
		err = updater.storeResponse(meta)
		if err != nil {
			updater.log.AuditErrf("Failed to store OCSP response: %s", err)
			stats.Inc("Errors.StoreResponse", 1)
			return
		}
		stats.Inc("StoredResponses", 1)
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

// oldOCSPResponsesTick looks for certificates with stale OCSP responses and
// generates/stores new ones
func (updater *OCSPUpdater) oldOCSPResponsesTick(ctx context.Context, batchSize int) error {
	tickStart := updater.clk.Now()
	statuses, err := updater.findStaleOCSPResponses(tickStart.Add(-updater.ocspMinTimeToExpiry), batchSize)
	if err != nil {
		updater.stats.Inc("Errors.FindStaleResponses", 1)
		updater.log.AuditErrf("Failed to find stale OCSP responses: %s", err)
		return err
	}
	if len(statuses) == batchSize {
		updater.stats.Inc("oldOCSPResponsesTick.FullTick", 1)
	}
	tickEnd := updater.clk.Now()
	updater.stats.TimingDuration("oldOCSPResponsesTick.QueryTime", tickEnd.Sub(tickStart))

	for _, s := range statuses {
		if !s.IsExpired && tickStart.After(s.NotAfter) {
			err := updater.markExpired(s)
			if err != nil {
				return err
			}
		}
	}

	return updater.generateOCSPResponses(ctx, statuses, updater.stats.NewScope("oldOCSPResponsesTick"))
}

type looper struct {
	clk                  clock.Clock
	stats                metrics.Scope
	batchSize            int
	tickDur              time.Duration
	tickFunc             func(context.Context, int) error
	name                 string
	failureBackoffFactor float64
	failureBackoffMax    time.Duration
	failures             int
}

func (l *looper) tick() {
	tickStart := l.clk.Now()
	ctx := context.TODO()
	err := l.tickFunc(ctx, l.batchSize)
	l.stats.TimingDuration("TickDuration", time.Since(tickStart))
	l.stats.Inc("Ticks", 1)
	tickEnd := tickStart.Add(time.Since(tickStart))
	expectedTickEnd := tickStart.Add(l.tickDur)
	if tickEnd.After(expectedTickEnd) {
		l.stats.Inc("LongTicks", 1)
	}

	// On success, sleep till it's time for the next tick. On failure, backoff.
	sleepDur := expectedTickEnd.Sub(tickEnd)
	if err != nil {
		l.stats.Inc("FailedTicks", 1)
		l.failures++
		sleepDur = core.RetryBackoff(l.failures, l.tickDur, l.failureBackoffMax, l.failureBackoffFactor)
	} else if l.failures > 0 {
		// If the tick was successful but previously there were failures reset
		// counter to 0
		l.failures = 0
	}

	// Sleep for the remaining tick period or for the backoff time
	l.clk.Sleep(sleepDur)
}

func (l *looper) loop() error {
	if l.batchSize == 0 || l.tickDur == 0 {
		return fmt.Errorf("Both batch size and tick duration are required, not running '%s' loop", l.name)
	}
	for {
		l.tick()
	}
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

	OldOCSPWindow cmd.ConfigDuration

	OldOCSPBatchSize int

	OCSPMinTimeToExpiry          cmd.ConfigDuration
	OCSPStaleMaxAge              cmd.ConfigDuration
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

func setupClients(c OCSPUpdaterConfig, stats metrics.Scope, clk clock.Clock) (
	core.CertificateAuthority,
	core.StorageAuthority,
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
	// Make a CA client that is only capable of signing OCSP.
	// TODO(jsha): Once we've fully moved to gRPC, replace this
	// with a plain caPB.NewOCSPGeneratorClient.
	cac := bgrpc.NewCertificateAuthorityClient(nil, capb.NewOCSPGeneratorClient(caConn))

	saConn, err := bgrpc.ClientSetup(c.SAService, tls, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(saConn))

	var apc akamaipb.AkamaiPurgerClient
	if c.AkamaiPurgerService != nil {
		apcConn, err := bgrpc.ClientSetup(c.AkamaiPurgerService, tls, clientMetrics, clk)
		cmd.FailOnError(err, "Failed ot load credentials and create gRPC connection to Akamai Purger service")
		apc = akamaipb.NewAkamaiPurgerClient(apcConn)
	}

	return cac, sac, apc
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

	scope, logger := cmd.StatsAndLogging(c.Syslog, conf.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	// Configure DB
	dbURL, err := conf.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, conf.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Could not connect to database")

	// Collect and periodically report DB metrics using the DBMap and prometheus scope.
	sa.InitDBMetrics(dbMap, scope)

	clk := cmd.Clock()
	cac, sac, apc := setupClients(conf, scope, clk)

	updater, err := newUpdater(
		scope,
		clk,
		dbMap,
		cac,
		sac,
		apc,
		// Necessary evil for now
		conf,
		c.Common.IssuerCert,
		logger,
	)
	cmd.FailOnError(err, "Failed to create updater")

	for _, l := range updater.loops {
		go func(loop *looper) {
			err = loop.loop()
			if err != nil {
				logger.AuditErr(err.Error())
			}
		}(l)
	}

	go cmd.CatchSignals(logger, nil)

	// Sleep forever (until signaled)
	select {}
}
