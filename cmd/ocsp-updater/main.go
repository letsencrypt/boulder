package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/akamai"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	pubPB "github.com/letsencrypt/boulder/publisher/proto"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
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

	cac  core.CertificateAuthority
	pubc core.Publisher
	sac  core.StorageAuthority

	// Used  to calculate how far back stale OCSP responses should be looked for
	ocspMinTimeToExpiry time.Duration
	// Used to calculate how far back missing SCT receipts should be looked for
	oldestIssuedSCT time.Duration
	// Number of CT logs we expect to have receipts from
	numLogs int

	loops []*looper

	ccu    *akamai.CachePurgeClient
	issuer *x509.Certificate
}

// This is somewhat gross but can be pared down a bit once the publisher and this
// are fully smooshed together
func newUpdater(
	stats metrics.Scope,
	clk clock.Clock,
	dbMap ocspDB,
	ca core.CertificateAuthority,
	pub core.Publisher,
	sac core.StorageAuthority,
	config cmd.OCSPUpdaterConfig,
	numLogs int,
	issuerPath string,
	log blog.Logger,
) (*OCSPUpdater, error) {
	if config.NewCertificateBatchSize == 0 ||
		config.OldOCSPBatchSize == 0 ||
		config.MissingSCTBatchSize == 0 {
		return nil, fmt.Errorf("Loop batch sizes must be non-zero")
	}
	if config.NewCertificateWindow.Duration == 0 ||
		config.OldOCSPWindow.Duration == 0 ||
		config.MissingSCTWindow.Duration == 0 {
		return nil, fmt.Errorf("Loop window sizes must be non-zero")
	}

	updater := OCSPUpdater{
		stats:               stats,
		clk:                 clk,
		dbMap:               dbMap,
		cac:                 ca,
		log:                 log,
		sac:                 sac,
		pubc:                pub,
		numLogs:             numLogs,
		ocspMinTimeToExpiry: config.OCSPMinTimeToExpiry.Duration,
		oldestIssuedSCT:     config.OldestIssuedSCT.Duration,
	}

	// Setup loops
	updater.loops = []*looper{
		{
			clk:                  clk,
			stats:                stats.NewScope("NewCertificates"),
			batchSize:            config.NewCertificateBatchSize,
			tickDur:              config.NewCertificateWindow.Duration,
			tickFunc:             updater.newCertificateTick,
			name:                 "NewCertificates",
			failureBackoffFactor: config.SignFailureBackoffFactor,
			failureBackoffMax:    config.SignFailureBackoffMax.Duration,
		},
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
		// The missing SCT loop doesn't need to know about failureBackoffFactor or
		// failureBackoffMax as it doesn't make any calls to the CA
		{
			clk:       clk,
			stats:     stats.NewScope("MissingSCTReceipts"),
			batchSize: config.MissingSCTBatchSize,
			tickDur:   config.MissingSCTWindow.Duration,
			tickFunc:  updater.missingReceiptsTick,
			name:      "MissingSCTReceipts",
		},
	}
	if config.RevokedCertificateBatchSize != 0 &&
		config.RevokedCertificateWindow.Duration != 0 {
		updater.loops = append(updater.loops, &looper{
			clk:                  clk,
			stats:                stats,
			batchSize:            config.RevokedCertificateBatchSize,
			tickDur:              config.RevokedCertificateWindow.Duration,
			tickFunc:             updater.revokedCertificatesTick,
			name:                 "RevokedCertificates",
			failureBackoffFactor: config.SignFailureBackoffFactor,
			failureBackoffMax:    config.SignFailureBackoffMax.Duration,
		})
	}

	// TODO(#1050): Remove this gate and the nil ccu checks below
	if config.AkamaiBaseURL != "" {
		issuer, err := core.LoadCert(issuerPath)
		ccu, err := akamai.NewCachePurgeClient(
			config.AkamaiBaseURL,
			config.AkamaiClientToken,
			config.AkamaiClientSecret,
			config.AkamaiAccessToken,
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
	}

	return &updater, nil
}

// sendPurge should only be called as a Goroutine as it will block until the purge
// request is successful
func (updater *OCSPUpdater) sendPurge(der []byte) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		updater.log.AuditErr(fmt.Sprintf("Failed to parse certificate for cache purge: %s", err))
		return
	}

	req, err := ocsp.CreateRequest(cert, updater.issuer, nil)
	if err != nil {
		updater.log.AuditErr(fmt.Sprintf("Failed to create OCSP request for cache purge: %s", err))
		return
	}

	// Create a GET style OCSP url for each endpoint in cert.OCSPServer (still waiting
	// on word from Akamai on how to properly purge cached POST requests, for now just
	// do GET)
	urls := []string{}
	for _, ocspServer := range cert.OCSPServer {
		urls = append(
			urls,
			path.Join(ocspServer, url.QueryEscape(base64.StdEncoding.EncodeToString(req))),
		)
	}

	err = updater.ccu.Purge(urls)
	if err != nil {
		updater.log.AuditErr(fmt.Sprintf("Failed to purge OCSP response from CDN: %s", err))
	}
}

func (updater *OCSPUpdater) findStaleOCSPResponses(oldestLastUpdatedTime time.Time, batchSize int) ([]core.CertificateStatus, error) {
	var statuses []core.CertificateStatus
	// TODO(@cpu): Once the notafter-backfill cmd has been run & completed then
	// the query below can be rewritten to use `AND NOT cs.isExpired`.
	_, err := updater.dbMap.Select(
		&statuses,
		`SELECT
			 cs.serial,
			 cs.status,
			 cs.revokedDate
			 FROM certificateStatus AS cs
			 JOIN certificates AS cert
			 ON cs.serial = cert.serial
			 WHERE cs.ocspLastUpdated < :lastUpdate
			 AND cert.expires > now()
			 ORDER BY cs.ocspLastUpdated ASC
			 LIMIT :limit`,
		map[string]interface{}{
			"lastUpdate": oldestLastUpdatedTime,
			"limit":      batchSize,
		},
	)
	if err == sql.ErrNoRows {
		return statuses, nil
	}
	return statuses, err
}

func (updater *OCSPUpdater) getCertificatesWithMissingResponses(batchSize int) ([]core.CertificateStatus, error) {
	var statuses []core.CertificateStatus
	var fields string
	if features.Enabled(features.CertStatusOptimizationsMigrated) {
		fields = sa.CertificateStatusFieldsv2
	} else {
		fields = sa.CertificateStatusFields
	}
	_, err := updater.dbMap.Select(
		&statuses,
		fmt.Sprintf(`SELECT %s FROM certificateStatus
			 WHERE ocspLastUpdated = 0
			 LIMIT :limit`, fields),
		map[string]interface{}{
			"limit": batchSize,
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
	var cert core.Certificate
	err := updater.dbMap.SelectOne(
		&cert,
		fmt.Sprintf("SELECT %s FROM certificates WHERE serial = :serial", sa.CertificateFields),
		map[string]interface{}{"serial": status.Serial},
	)
	if err != nil {
		return nil, err
	}

	_, err = x509.ParseCertificate(cert.DER)
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

	// Purge OCSP response from CDN, gated on client having been initialized
	if updater.ccu != nil {
		go updater.sendPurge(cert.DER)
	}

	return &status, nil
}

func (updater *OCSPUpdater) generateRevokedResponse(ctx context.Context, status core.CertificateStatus) (*core.CertificateStatus, error) {
	cert, err := updater.sac.GetCertificate(ctx, status.Serial)
	if err != nil {
		return nil, err
	}

	signRequest := core.OCSPSigningRequest{
		CertDER:   cert.DER,
		Status:    string(core.OCSPStatusRevoked),
		Reason:    status.RevokedReason,
		RevokedAt: status.RevokedDate,
	}

	ocspResponse, err := updater.cac.GenerateOCSP(ctx, signRequest)
	if err != nil {
		return nil, err
	}

	now := updater.clk.Now()
	status.OCSPLastUpdated = now
	status.OCSPResponse = ocspResponse

	// Purge OCSP response from CDN, gated on client having been initialized
	if updater.ccu != nil {
		go updater.sendPurge(cert.DER)
	}

	return &status, nil
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

// newCertificateTick checks for certificates issued since the last tick and
// generates and stores OCSP responses for these certs
func (updater *OCSPUpdater) newCertificateTick(ctx context.Context, batchSize int) error {
	// Check for anything issued between now and previous tick and generate first
	// OCSP responses
	statuses, err := updater.getCertificatesWithMissingResponses(batchSize)
	if err != nil {
		updater.stats.Inc("Errors.FindMissingResponses", 1)
		updater.log.AuditErr(fmt.Sprintf("Failed to find certificates with missing OCSP responses: %s", err))
		return err
	}

	return updater.generateOCSPResponses(ctx, statuses)
}

func (updater *OCSPUpdater) findRevokedCertificatesToUpdate(batchSize int) ([]core.CertificateStatus, error) {
	var statuses []core.CertificateStatus
	var fields string
	if features.Enabled(features.CertStatusOptimizationsMigrated) {
		fields = sa.CertificateStatusFieldsv2
	} else {
		fields = sa.CertificateStatusFields
	}
	_, err := updater.dbMap.Select(
		&statuses,
		fmt.Sprintf(`SELECT %s FROM certificateStatus
		 WHERE status = :revoked
		 AND ocspLastUpdated <= revokedDate
		 LIMIT :limit`, fields),
		map[string]interface{}{
			"revoked": string(core.OCSPStatusRevoked),
			"limit":   batchSize,
		},
	)
	return statuses, err
}

func (updater *OCSPUpdater) revokedCertificatesTick(ctx context.Context, batchSize int) error {
	statuses, err := updater.findRevokedCertificatesToUpdate(batchSize)
	if err != nil {
		updater.stats.Inc("Errors.FindRevokedCertificates", 1)
		updater.log.AuditErr(fmt.Sprintf("Failed to find revoked certificates: %s", err))
		return err
	}

	for _, status := range statuses {
		meta, err := updater.generateRevokedResponse(ctx, status)
		if err != nil {
			updater.log.AuditErr(fmt.Sprintf("Failed to generate revoked OCSP response: %s", err))
			updater.stats.Inc("Errors.RevokedResponseGeneration", 1)
			return err
		}
		err = updater.storeResponse(meta)
		if err != nil {
			updater.stats.Inc("Errors.StoreRevokedResponse", 1)
			updater.log.AuditErr(fmt.Sprintf("Failed to store OCSP response: %s", err))
			continue
		}
	}
	return nil
}

func (updater *OCSPUpdater) generateOCSPResponses(ctx context.Context, statuses []core.CertificateStatus) error {
	for _, status := range statuses {
		meta, err := updater.generateResponse(ctx, status)
		if err != nil {
			updater.log.AuditErr(fmt.Sprintf("Failed to generate OCSP response: %s", err))
			updater.stats.Inc("Errors.ResponseGeneration", 1)
			return err
		}
		updater.stats.Inc("GeneratedResponses", 1)
		err = updater.storeResponse(meta)
		if err != nil {
			updater.log.AuditErr(fmt.Sprintf("Failed to store OCSP response: %s", err))
			updater.stats.Inc("Errors.StoreResponse", 1)
			continue
		}
		updater.stats.Inc("StoredResponses", 1)
	}
	return nil
}

// oldOCSPResponsesTick looks for certificates with stale OCSP responses and
// generates/stores new ones
func (updater *OCSPUpdater) oldOCSPResponsesTick(ctx context.Context, batchSize int) error {
	now := time.Now()
	statuses, err := updater.findStaleOCSPResponses(now.Add(-updater.ocspMinTimeToExpiry), batchSize)
	if err != nil {
		updater.stats.Inc("Errors.FindStaleResponses", 1)
		updater.log.AuditErr(fmt.Sprintf("Failed to find stale OCSP responses: %s", err))
		return err
	}

	return updater.generateOCSPResponses(ctx, statuses)
}

func (updater *OCSPUpdater) getSerialsIssuedSince(since time.Time, batchSize int) ([]string, error) {
	var allSerials []string
	for {
		serials := []string{}
		_, err := updater.dbMap.Select(
			&serials,
			`SELECT serial FROM certificates
			 WHERE issued > :since
			 ORDER BY issued ASC
			 LIMIT :limit OFFSET :offset`,
			map[string]interface{}{
				"since":  since,
				"limit":  batchSize,
				"offset": len(allSerials),
			},
		)
		if err == sql.ErrNoRows || len(serials) == 0 {
			break
		}
		if err != nil {
			return nil, err
		}
		allSerials = append(allSerials, serials...)

		if len(serials) < batchSize {
			break
		}
	}
	return allSerials, nil
}

func (updater *OCSPUpdater) getNumberOfReceipts(serial string) (int, error) {
	var count int
	err := updater.dbMap.SelectOne(
		&count,
		"SELECT COUNT(id) FROM sctReceipts WHERE certificateSerial = :serial",
		map[string]interface{}{"serial": serial},
	)
	return count, err
}

// missingReceiptsTick looks for certificates without the correct number of SCT
// receipts and retrieves them
func (updater *OCSPUpdater) missingReceiptsTick(ctx context.Context, batchSize int) error {
	now := updater.clk.Now()
	since := now.Add(-updater.oldestIssuedSCT)
	serials, err := updater.getSerialsIssuedSince(since, batchSize)
	if err != nil {
		updater.log.AuditErr(fmt.Sprintf("Failed to get certificate serials: %s", err))
		return err
	}

	for _, serial := range serials {
		count, err := updater.getNumberOfReceipts(serial)
		if err != nil {
			updater.log.AuditErr(fmt.Sprintf("Failed to get number of SCT receipts for certificate: %s", err))
			continue
		}
		if count >= updater.numLogs {
			continue
		}
		cert, err := updater.sac.GetCertificate(ctx, serial)
		if err != nil {
			updater.log.AuditErr(fmt.Sprintf("Failed to get certificate: %s", err))
			continue
		}
		_ = updater.pubc.SubmitToCT(ctx, cert.DER)
	}
	return nil
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

	// After we have all the stats stuff out of the way let's check if the tick
	// function failed, if the reason is the HSM is dead increase the length of
	// sleepDur using the exponentially increasing duration returned by core.RetryBackoff.
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

const clientName = "OCSP"

type config struct {
	OCSPUpdater cmd.OCSPUpdaterConfig

	Statsd cmd.StatsdConfig

	Syslog cmd.SyslogConfig

	Common struct {
		IssuerCert string
		CT         struct {
			Logs []cmd.LogDescription
		}
	}
}

func setupClients(c cmd.OCSPUpdaterConfig, stats metrics.Scope) (
	core.CertificateAuthority,
	core.Publisher,
	core.StorageAuthority,
) {
	amqpConf := c.AMQP
	cac, err := rpc.NewCertificateAuthorityClient(clientName, amqpConf, stats)
	cmd.FailOnError(err, "Unable to create CA client")

	var pubc core.Publisher
	if c.Publisher != nil {
		conn, err := bgrpc.ClientSetup(c.Publisher, stats)
		cmd.FailOnError(err, "Failed to load credentials and create connection to service")
		pubc = bgrpc.NewPublisherClientWrapper(pubPB.NewPublisherClient(conn), c.Publisher.Timeout.Duration)
	} else {
		pubc, err = rpc.NewPublisherClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Unable to create Publisher client")
	}
	sac, err := rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
	cmd.FailOnError(err, "Unable to create SA client")
	return cac, pubc, sac
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

	go cmd.DebugServer(conf.DebugAddr)

	stats, auditlogger := cmd.StatsAndLogging(c.Statsd, c.Syslog)
	scope := metrics.NewStatsdScope(stats, "OCSPUpdater")
	defer auditlogger.AuditPanic()
	auditlogger.Info(cmd.VersionString(clientName))

	go cmd.ProfileCmd(scope)

	// Configure DB
	dbURL, err := conf.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, conf.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Could not connect to database")
	go sa.ReportDbConnCount(dbMap, scope)

	cac, pubc, sac := setupClients(conf, scope)

	updater, err := newUpdater(
		scope,
		clock.Default(),
		dbMap,
		cac,
		pubc,
		sac,
		// Necessary evil for now
		conf,
		len(c.Common.CT.Logs),
		c.Common.IssuerCert,
		auditlogger,
	)

	cmd.FailOnError(err, "Failed to create updater")

	for _, l := range updater.loops {
		go func(loop *looper) {
			err = loop.loop()
			if err != nil {
				auditlogger.AuditErr(err.Error())
			}
		}(l)
	}

	// Sleep forever (until signaled)
	select {}
}
