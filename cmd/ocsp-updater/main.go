package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/akamai"
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
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/context"
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

	ccu           *akamai.CachePurgeClient
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
	config cmd.OCSPUpdaterConfig,
	issuerPath string,
	log blog.Logger,
) (*OCSPUpdater, error) {
	if config.OldOCSPBatchSize == 0 ||
		config.RevokedCertificateBatchSize == 0 {
		return nil, fmt.Errorf("Loop batch sizes must be non-zero")
	}
	if config.OldOCSPWindow.Duration == 0 ||
		config.RevokedCertificateWindow.Duration == 0 {
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
		{
			clk:                  clk,
			stats:                stats.NewScope("RevokedCertificates"),
			batchSize:            config.RevokedCertificateBatchSize,
			tickDur:              config.RevokedCertificateWindow.Duration,
			tickFunc:             updater.revokedCertificatesTick,
			name:                 "RevokedCertificates",
			failureBackoffFactor: config.SignFailureBackoffFactor,
			failureBackoffMax:    config.SignFailureBackoffMax.Duration,
		},
	}

	if config.AkamaiBaseURL != "" {
		issuer, err := core.LoadCert(issuerPath)
		if err != nil {
			return nil, err
		}
		ccu, err := akamai.NewCachePurgeClient(
			config.AkamaiBaseURL,
			config.AkamaiClientToken,
			config.AkamaiClientSecret,
			config.AkamaiAccessToken,
			config.AkamaiV3Network,
			config.AkamaiPurgeRetries,
			config.AkamaiPurgeRetryBackoff.Duration,
			log,
			stats,
		)
		if err != nil {
			return nil, err
		}
		updater.ccu = ccu
		updater.issuer = issuer
	} else if apc != nil {
		issuer, err := core.LoadCert(issuerPath)
		if err != nil {
			return nil, err
		}
		updater.issuer = issuer
		updater.purgerService = apc
	}

	return &updater, nil
}

func (updater *OCSPUpdater) findStaleOCSPResponses(oldestLastUpdatedTime time.Time, batchSize int) ([]core.CertificateStatus, error) {
	var statuses []core.CertificateStatus
	// TODO(@cpu): Once the notafter-backfill cmd has been run & completed then
	// the query below can be rewritten to use `AND NOT cs.isExpired`.
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

type responseMeta struct {
	*core.OCSPResponse
	*core.CertificateStatus
}

func (updater *OCSPUpdater) generateResponse(ctx context.Context, status core.CertificateStatus) (*core.CertificateStatus, error) {
	cert, err := sa.SelectCertificate(
		updater.dbMap,
		"WHERE serial = ?",
		status.Serial,
	)
	if err != nil {
		return nil, err
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

// generateRevokedResponse takes a core.CertificateStatus and updates it with a revoked OCSP response
// for the certificate it represents. generateRevokedResponse then returns the updated status and a
// list of OCSP request URLs that should be purged or an error.
func (updater *OCSPUpdater) generateRevokedResponse(ctx context.Context, status core.CertificateStatus) (*core.CertificateStatus, []string, error) {
	cert, err := updater.sac.GetCertificate(ctx, status.Serial)
	if err != nil {
		return nil, nil, err
	}

	signRequest := core.OCSPSigningRequest{
		CertDER:   cert.DER,
		Status:    string(core.OCSPStatusRevoked),
		Reason:    status.RevokedReason,
		RevokedAt: status.RevokedDate,
	}

	ocspResponse, err := updater.cac.GenerateOCSP(ctx, signRequest)
	if err != nil {
		return nil, nil, err
	}

	now := updater.clk.Now()
	status.OCSPLastUpdated = now
	status.OCSPResponse = ocspResponse

	// If cache client is populated generate purge URLs
	var purgeURLs []string
	if updater.ccu != nil || updater.purgerService != nil {
		purgeURLs, err = akamai.GeneratePurgeURLs(cert.DER, updater.issuer)
		if err != nil {
			return nil, nil, err
		}
	}

	return &status, purgeURLs, nil
}

func (updater *OCSPUpdater) storeResponse(status *core.CertificateStatus) error {
	// Update the certificateStatus table with the new OCSP response, the status
	// WHERE is used make sure we don't overwrite a revoked response with a one
	// containing a 'good' status and that we don't do the inverse when the OCSP
	// status should be 'good'.
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

func (updater *OCSPUpdater) findRevokedCertificatesToUpdate(batchSize int) ([]core.CertificateStatus, error) {
	const query = "WHERE NOT isExpired AND status = ? AND ocspLastUpdated <= revokedDate LIMIT ?"
	statuses, err := sa.SelectCertificateStatuses(
		updater.dbMap,
		query,
		string(core.OCSPStatusRevoked),
		batchSize,
	)
	return statuses, err
}

func (updater *OCSPUpdater) revokedCertificatesTick(ctx context.Context, batchSize int) error {
	statuses, err := updater.findRevokedCertificatesToUpdate(batchSize)
	if err != nil {
		updater.stats.Inc("Errors.FindRevokedCertificates", 1)
		updater.log.AuditErrf("Failed to find revoked certificates: %s", err)
		return err
	}
	if len(statuses) == batchSize {
		updater.stats.Inc("revokedCertificatesTick.FullTick", 1)
	}

	var allPurgeURLs []string
	for _, status := range statuses {
		// It's possible that, if our ticks are fast enough (mainly in tests), we
		// will get a certificate status where the ocspLastUpdated == revokedDate
		// and the certificate has already been revoked. In order to avoid
		// generating a new response and purging the existing response, quickly
		// check the actual response in this rare case.
		if status.OCSPLastUpdated.Equal(status.RevokedDate) {
			resp, err := ocsp.ParseResponse(status.OCSPResponse, nil)
			if err != nil {
				updater.log.AuditErrf("Failed to parse OCSP response: %s", err)
				return err
			}
			if resp.Status == ocsp.Revoked {
				// We already generated a revoked response, don't bother doing it again
				continue
			}
		}
		meta, purgeURLs, err := updater.generateRevokedResponse(ctx, status)
		if err != nil {
			updater.log.AuditErrf("Failed to generate revoked OCSP response: %s", err)
			updater.stats.Inc("Errors.RevokedResponseGeneration", 1)
			return err
		}
		allPurgeURLs = append(allPurgeURLs, purgeURLs...)
		err = updater.storeResponse(meta)
		if err != nil {
			updater.stats.Inc("Errors.StoreRevokedResponse", 1)
			updater.log.AuditErrf("Failed to store OCSP response: %s", err)
			continue
		}
	}

	if len(allPurgeURLs) > 0 {
		if updater.ccu != nil {
			err = updater.ccu.Purge(allPurgeURLs)
			if err != nil {
				updater.log.AuditErrf("Failed to purge OCSP response from CDN: %s", err)
				return err
			}
		} else if updater.purgerService != nil {
			go func() {
				_, err = updater.purgerService.Purge(context.Background(), &akamaipb.PurgeRequest{
					Urls: allPurgeURLs,
				})
				if err != nil {
					updater.log.Errf("Request to Akamai purger service failed: %s", err)
				}
			}()
		}
	}

	return nil
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
	OCSPUpdater cmd.OCSPUpdaterConfig

	Statsd cmd.StatsdConfig

	Syslog cmd.SyslogConfig

	Common struct {
		IssuerCert string
	}
}

func setupClients(c cmd.OCSPUpdaterConfig, stats metrics.Scope, clk clock.Clock) (
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

	conn, err := bgrpc.ClientSetup(c.SAService, tls, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(conn))

	var apc akamaipb.AkamaiPurgerClient
	if c.AkamaiPurgerService != nil {
		conn, err := bgrpc.ClientSetup(c.AkamaiPurgerService, tls, clientMetrics, clk)
		cmd.FailOnError(err, "Failed ot load credentials and create gRPC connection to Akamai Purger service")
		apc = akamaipb.NewAkamaiPurgerClient(conn)
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
	go sa.ReportDbConnCount(dbMap, scope)

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
