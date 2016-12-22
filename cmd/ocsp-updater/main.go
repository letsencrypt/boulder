package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/akamai"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	pubPB "github.com/letsencrypt/boulder/publisher/proto"
	"github.com/letsencrypt/boulder/rpc"
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

	cac  core.CertificateAuthority
	pubc core.Publisher
	sac  core.StorageAuthority

	// Used to calculate how far back stale OCSP responses should be looked for
	ocspMinTimeToExpiry time.Duration
	// Used to caculate how far back in time the findStaleOCSPResponse will look
	ocspStaleMaxAge time.Duration
	// Used to calculate how far back missing SCT receipts should be looked for
	oldestIssuedSCT time.Duration
	// Maximum number of individual OCSP updates to attempt in parallel. Making
	// these requests in parallel allows us to get higher total throughput.
	parallelGenerateOCSPRequests int
	// Logs we expect to have SCT receipts for. Missing logs will be resubmitted to.
	logs []*ctLog

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
	logConfigs []cmd.LogDescription,
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
	if config.OCSPStaleMaxAge.Duration == 0 {
		// Default to 30 days
		config.OCSPStaleMaxAge = cmd.ConfigDuration{Duration: time.Hour * 24 * 30}
	}
	if config.ParallelGenerateOCSPRequests == 0 {
		// Default to 1
		config.ParallelGenerateOCSPRequests = 1
	}

	logs := make([]*ctLog, len(logConfigs))
	for i, logConfig := range logConfigs {
		l, err := newLog(logConfig)
		if err != nil {
			return nil, err
		}
		logs[i] = l
	}

	updater := OCSPUpdater{
		stats:                        stats,
		clk:                          clk,
		dbMap:                        dbMap,
		cac:                          ca,
		log:                          log,
		sac:                          sac,
		pubc:                         pub,
		logs:                         logs,
		ocspMinTimeToExpiry:          config.OCSPMinTimeToExpiry.Duration,
		ocspStaleMaxAge:              config.OCSPStaleMaxAge.Duration,
		oldestIssuedSCT:              config.OldestIssuedSCT.Duration,
		parallelGenerateOCSPRequests: config.ParallelGenerateOCSPRequests,
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

	// Create a GET and special Akamai POST style OCSP url for each endpoint in cert.OCSPServer
	urls := []string{}
	reverse := func(b []byte) []byte {
		for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return b
	}
	for _, ocspServer := range cert.OCSPServer {
		if !strings.HasSuffix(ocspServer, "/") {
			ocspServer += "/"
		}
		// Generate GET url
		urls = append(
			urls,
			fmt.Sprintf("%s%s", ocspServer, url.QueryEscape(base64.StdEncoding.EncodeToString(req))),
		)
		// Generate POST url, format is the URL that was POST'd to with a query string with
		// the parameter 'body-mdy' and the value of the first two uint32s in little endian
		// order in hex of the MD5 hash of the OCSP request body.
		hash := md5.Sum(der)
		urls = append(
			urls,
			fmt.Sprintf("%s?body-mdy=%x%x", ocspServer, reverse(hash[0:4]), reverse(hash[4:8])),
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
	now := updater.clk.Now()
	maxAgeCutoff := now.Add(-updater.ocspStaleMaxAge)

	// If CertStatusOptimizationsMigrated is enabled then we can do this query
	// using only the `certificateStatus` table, saving an expensive JOIN and
	// improving performance substantially
	var err error
	if features.Enabled(features.CertStatusOptimizationsMigrated) {
		_, err = updater.dbMap.Select(
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
		// If the migration hasn't been applied we don't have the `isExpired` or
		// `notAfter` fields on the certificate status table to use and must do the
		// expensive JOIN on `certificates`
	} else {
		_, err = updater.dbMap.Select(
			&statuses,
			`SELECT
				 cs.serial,
				 cs.status,
				 cs.revokedDate
				 FROM certificateStatus AS cs
				 JOIN certificates AS cert
				 ON cs.serial = cert.serial
				 WHERE cs.ocspLastUpdated > :maxAge
				 AND cs.ocspLastUpdated < :lastUpdate
				 AND cert.expires > now()
				 ORDER BY cs.ocspLastUpdated ASC
				 LIMIT :limit`,
			map[string]interface{}{
				"lastUpdate": oldestLastUpdatedTime,
				"maxAge":     maxAgeCutoff,
				"limit":      batchSize,
			},
		)
	}
	if err == sql.ErrNoRows {
		return statuses, nil
	}
	return statuses, err
}

func (updater *OCSPUpdater) getCertificatesWithMissingResponses(batchSize int) ([]core.CertificateStatus, error) {
	const query = "WHERE ocspLastUpdated = 0 LIMIT ?"
	var statuses []core.CertificateStatus
	var err error
	if features.Enabled(features.CertStatusOptimizationsMigrated) {
		statuses, err = sa.SelectCertificateStatusesv2(
			updater.dbMap,
			query,
			batchSize,
		)
	} else {
		statuses, err = sa.SelectCertificateStatuses(
			updater.dbMap,
			query,
			batchSize,
		)
	}
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

	return updater.generateOCSPResponses(ctx, statuses, updater.stats.NewScope("newCertificateTick"))
}

func (updater *OCSPUpdater) findRevokedCertificatesToUpdate(batchSize int) ([]core.CertificateStatus, error) {
	const query = "WHERE status = ? AND ocspLastUpdated <= revokedDate LIMIT ?"
	var statuses []core.CertificateStatus
	var err error
	if features.Enabled(features.CertStatusOptimizationsMigrated) {
		statuses, err = sa.SelectCertificateStatusesv2(
			updater.dbMap,
			query,
			string(core.OCSPStatusRevoked),
			batchSize,
		)
	} else {
		statuses, err = sa.SelectCertificateStatuses(
			updater.dbMap,
			query,
			string(core.OCSPStatusRevoked),
			batchSize,
		)
	}
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
	done := func() {
		<-sem // Indicate there's more capacity.
	}

	work := func(status core.CertificateStatus) {
		defer done()
		meta, err := updater.generateResponse(ctx, status)
		if err != nil {
			updater.log.AuditErr(fmt.Sprintf("Failed to generate OCSP response: %s", err))
			stats.Inc("Errors.ResponseGeneration", 1)
			return
		}
		updater.stats.Inc("GeneratedResponses", 1)
		err = updater.storeResponse(meta)
		if err != nil {
			updater.log.AuditErr(fmt.Sprintf("Failed to store OCSP response: %s", err))
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
		updater.log.AuditErr(fmt.Sprintf("Failed to find stale OCSP responses: %s", err))
		return err
	}
	tickEnd := updater.clk.Now()
	updater.stats.TimingDuration("oldOCSPResponsesTick.QueryTime", tickEnd.Sub(tickStart))

	// If the CertStatusOptimizationsMigrated flag is set then we need to
	// opportunistically update the certificateStatus `isExpired` column for expired
	// certificates we come across
	if features.Enabled(features.CertStatusOptimizationsMigrated) {
		for _, s := range statuses {
			if !s.IsExpired && tickStart.After(s.NotAfter) {
				err := updater.markExpired(s)
				if err != nil {
					return err
				}
			}
		}
	}

	return updater.generateOCSPResponses(ctx, statuses, updater.stats.NewScope("oldOCSPResponsesTick"))
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

// getSubmittedReceipts returns the IDs of the CT logs that have returned a SCT
// receipt for the given certificate serial
func (updater *OCSPUpdater) getSubmittedReceipts(serial string) ([]string, error) {
	var logIDs []string
	_, err := updater.dbMap.Select(
		&logIDs,
		`SELECT logID
		FROM sctReceipts
		WHERE certificateSerial = :serial`,
		map[string]interface{}{"serial": serial},
	)
	return logIDs, err
}

// missingLogIDs examines a list of log IDs that have given a SCT receipt for
// a certificate and returns a list of the configured logs that are not
// present. This is the set of logs we need to resubmit this certificate to in
// order to obtain a full compliment of SCTs
func (updater *OCSPUpdater) missingLogs(logIDs []string) []*ctLog {
	var missingLogs []*ctLog

	presentMap := make(map[string]bool)
	for _, logID := range logIDs {
		presentMap[logID] = true
	}

	for _, l := range updater.logs {
		if _, present := presentMap[l.logID]; !present {
			missingLogs = append(missingLogs, l)
		}
	}

	return missingLogs
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
		// First find the logIDs that have provided a SCT for the serial
		logIDs, err := updater.getSubmittedReceipts(serial)
		if err != nil {
			updater.log.AuditErr(fmt.Sprintf(
				"Failed to get CT log IDs of SCT receipts for certificate: %s", err))
			continue
		}

		// Next, check if any of the configured CT logs are missing from the list of
		// logs that have given SCTs for this serial
		missingLogs := updater.missingLogs(logIDs)
		if len(missingLogs) == 0 {
			// If all of the logs have provided a SCT we're done for this serial
			continue
		}

		// Otherwise, we need to get the certificate from the SA & submit it to each
		// of the missing logs to obtain SCTs.
		cert, err := updater.sac.GetCertificate(ctx, serial)
		if err != nil {
			updater.log.AuditErr(fmt.Sprintf("Failed to get certificate: %s", err))
			continue
		}

		// If the feature flag is enabled, only send the certificate to the missing
		// logs using the `SubmitToSingleCT` endpoint that was added for this
		// purpose
		if features.Enabled(features.ResubmitMissingSCTsOnly) {
			for _, log := range missingLogs {
				_ = updater.pubc.SubmitToSingleCT(ctx, log.uri, log.key, cert.DER)
			}
		} else {
			// Otherwise, use the classic behaviour and submit the certificate to
			// every log to get SCTS using the pre-existing `SubmitToCT` endpoint
			_ = updater.pubc.SubmitToCT(ctx, cert.DER)
		}
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

// a ctLog contains the pre-processed logID and URI for a CT log. The ocsp-updater
// creates these out of cmd.LogDescription's from its config
type ctLog struct {
	logID string
	key   string
	uri   string
}

func newLog(logConfig cmd.LogDescription) (*ctLog, error) {
	logPK, err := base64.StdEncoding.DecodeString(logConfig.Key)
	if err != nil {
		return nil, err
	}

	logPKHash := sha256.Sum256(logPK)
	logID := base64.StdEncoding.EncodeToString(logPKHash[:])
	return &ctLog{logID: logID, key: logConfig.Key, uri: logConfig.URI}, nil
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

	var cac core.CertificateAuthority
	if c.CAService != nil {
		conn, err := bgrpc.ClientSetup(c.CAService, stats)
		cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to CA")
		cac = bgrpc.NewCertificateAuthorityClient(capb.NewCertificateAuthorityClient(conn))
	} else {
		var err error
		cac, err = rpc.NewCertificateAuthorityClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Unable to create CA client")
	}

	conn, err := bgrpc.ClientSetup(c.Publisher, stats)
	cmd.FailOnError(err, "Failed to load credentials and create connection to service")
	pubc := bgrpc.NewPublisherClientWrapper(pubPB.NewPublisherClient(conn))

	var sac core.StorageAuthority
	if c.SAService != nil {
		conn, err := bgrpc.ClientSetup(c.SAService, stats)
		cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
		sac = bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(conn))
	} else {
		sac, err = rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Unable to create SA client")
	}

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

	stats, auditlogger := cmd.StatsAndLogging(c.Statsd, c.Syslog)
	scope := metrics.NewStatsdScope(stats, "OCSPUpdater")
	defer auditlogger.AuditPanic()
	auditlogger.Info(cmd.VersionString(clientName))

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
		c.Common.CT.Logs,
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

	go cmd.DebugServer(conf.DebugAddr)
	go cmd.ProfileCmd(scope)

	// Sleep forever (until signaled)
	select {}
}
