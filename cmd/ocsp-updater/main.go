// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/x509"
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

// OCSPUpdater contains the useful objects for the Updater
type OCSPUpdater struct {
	stats statsd.Statter
	log   *blog.AuditLogger
	clk   clock.Clock

	dbMap *gorp.DbMap

	cac  core.CertificateAuthority
	pubc core.Publisher
	sac  core.StorageAuthority

	// Used  to calculate how far back stale OCSP responses should be looked for
	ocspMinTimeToExpiry time.Duration
	// Used to calculate how far back missing SCT receipts should be looked for
	oldestIssuedSCT time.Duration
	// Number of CT logs we expect to have receipts from
	numLogs int

	newCertificatesLoop    *looper
	oldOCSPResponsesLoop   *looper
	missingSCTReceiptsLoop *looper
}

// This is somewhat gross but can be pared down a bit once the publisher and this
// are fully smooshed together
func newUpdater(
	stats statsd.Statter,
	clk clock.Clock,
	dbMap *gorp.DbMap,
	ca core.CertificateAuthority,
	pub core.Publisher,
	sac core.StorageAuthority,
	config cmd.OCSPUpdaterConfig,
	numLogs int,
) (*OCSPUpdater, error) {
	if config.NewCertificateBatchSize == 0 ||
		config.OldOCSPBatchSize == 0 {
		return nil, fmt.Errorf("Batch sizes must be non-zero")
	}

	updater := OCSPUpdater{
		stats:               stats,
		clk:                 clk,
		dbMap:               dbMap,
		cac:                 ca,
		log:                 blog.GetAuditLogger(),
		numLogs:             numLogs,
		ocspMinTimeToExpiry: config.OCSPMinTimeToExpiry.Duration,
		oldestIssuedSCT:     config.OldestIssuedSCT.Duration,
	}

	// Setup loops
	updater.newCertificatesLoop = &looper{
		clk:       clk,
		stats:     stats,
		batchSize: config.NewCertificateBatchSize,
		tickDur:   config.NewCertificateWindow.Duration,
		tickFunc:  updater.newCertificateTick,
		name:      "NewCertificates",
	}
	updater.oldOCSPResponsesLoop = &looper{
		clk:       clk,
		stats:     stats,
		batchSize: config.OldOCSPBatchSize,
		tickDur:   config.OldOCSPWindow.Duration,
		tickFunc:  updater.oldOCSPResponsesTick,
		name:      "OldOCSPResponses",
	}
	updater.missingSCTReceiptsLoop = &looper{
		clk:       clk,
		stats:     stats,
		batchSize: config.MissingSCTBatchSize,
		tickDur:   config.MissingSCTWindow.Duration,
		tickFunc:  updater.missingReceiptsTick,
		name:      "MissingSCTReceipts",
	}

	updater.ocspMinTimeToExpiry = config.OCSPMinTimeToExpiry.Duration

	return &updater, nil
}

func (updater *OCSPUpdater) findStaleOCSPResponses(oldestLastUpdatedTime time.Time, batchSize int) ([]core.CertificateStatus, error) {
	var statuses []core.CertificateStatus
	_, err := updater.dbMap.Select(
		&statuses,
		`SELECT cs.*
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
	_, err := updater.dbMap.Select(
		&statuses,
		`SELECT * FROM certificateStatus
			 WHERE ocspLastUpdated = 0
			 LIMIT :limit`,
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

func (updater *OCSPUpdater) generateResponse(status core.CertificateStatus) (responseMeta, error) {
	var cert core.Certificate
	err := updater.dbMap.SelectOne(
		&cert,
		"SELECT * FROM certificates WHERE serial = :serial",
		map[string]interface{}{"serial": status.Serial},
	)
	if err != nil {
		return responseMeta{}, err
	}

	_, err = x509.ParseCertificate(cert.DER)
	if err != nil {
		return responseMeta{}, err
	}

	signRequest := core.OCSPSigningRequest{
		CertDER:   cert.DER,
		Reason:    status.RevokedReason,
		Status:    string(status.Status),
		RevokedAt: status.RevokedDate,
	}

	ocspResponse, err := updater.cac.GenerateOCSP(signRequest)
	if err != nil {
		return responseMeta{}, err
	}

	timestamp := updater.clk.Now()
	status.OCSPLastUpdated = timestamp
	ocspResp := &core.OCSPResponse{
		Serial:    cert.Serial,
		CreatedAt: timestamp,
		Response:  ocspResponse,
	}
	return responseMeta{ocspResp, &status}, nil
}

func (updater *OCSPUpdater) storeResponse(tx *gorp.Transaction, meta responseMeta) error {
	// Record the response.
	err := tx.Insert(meta.OCSPResponse)
	if err != nil {
		return err
	}

	// Reset the update clock
	_, err = tx.Update(meta.CertificateStatus)
	if err != nil {
		return err
	}

	// Done
	return nil
}

// newCertificateTick checks for certificates issued since the last tick and
// generates and stores OCSP responses for these certs
func (updater *OCSPUpdater) newCertificateTick(batchSize int) {
	// Check for anything issued between now and previous tick and generate first
	// OCSP responses
	statuses, err := updater.getCertificatesWithMissingResponses(batchSize)
	if err != nil {
		return
	}

	updater.generateOCSPResponses(statuses)
}

func (updater *OCSPUpdater) generateOCSPResponses(statuses []core.CertificateStatus) {
	responses := []responseMeta{}
	for _, status := range statuses {
		meta, err := updater.generateResponse(status)
		if err != nil {
			updater.log.AuditErr(fmt.Errorf("Failed to generate OCSP response: %s", err))
			updater.stats.Inc("OCSP.Errors.ResponseGeneration", 1, 1.0)
			continue
		}
		responses = append(responses, meta)
		updater.stats.Inc("OCSP.GeneratedResponses", 1, 1.0)
	}

	tx, err := updater.dbMap.Begin()
	if err != nil {
		updater.log.AuditErr(fmt.Errorf("Failed to open OCSP response transaction: %s", err))
		updater.stats.Inc("OCSP.Errors.OpenTransaction", 1, 1.0)
		return
	}
	for _, meta := range responses {
		err = updater.storeResponse(tx, meta)
		if err != nil {
			updater.log.AuditErr(fmt.Errorf("Failed to store OCSP response: %s", err))
			updater.stats.Inc("OCSP.Errors.StoreResponse", 1, 1.0)
			tx.Rollback()
			return
		}
	}
	err = tx.Commit()
	if err != nil {
		updater.log.AuditErr(fmt.Errorf("Failed to commit OCSP response transaction: %s", err))
		updater.stats.Inc("OCSP.Errors.CommitTransaction", 1, 1.0)
		return
	}
	updater.stats.Inc("OCSP.StoredResponses", int64(len(responses)), 1.0)

	return
}

// oldOCSPResponsesTick looks for certificates with stale OCSP responses and
// generates/stores new ones
func (updater *OCSPUpdater) oldOCSPResponsesTick(batchSize int) {
	now := time.Now()
	statuses, err := updater.findStaleOCSPResponses(now.Add(-updater.ocspMinTimeToExpiry), batchSize)
	if err != nil {
		updater.stats.Inc("OCSP.Errors.FindStaleResponses", 1, 1.0)
		updater.log.AuditErr(fmt.Errorf("Failed to find stale OCSP responses: %s", err))
		return
	}

	updater.generateOCSPResponses(statuses)
}

func (updater *OCSPUpdater) getSerialsIssuedSince(since time.Time, batchSize int) ([]string, error) {
	var serials []string
	_, err := updater.dbMap.Select(
		&serials,
		`SELECT serial FROM certificates
			 WHERE issued > :since
			 ORDER BY issued ASC
			 LIMIT :limit`,
		map[string]interface{}{
			"since": since,
			"limit": batchSize,
		},
	)
	if err == sql.ErrNoRows {
		return serials, nil
	}
	return serials, err
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
func (updater *OCSPUpdater) missingReceiptsTick(batchSize int) {
	now := updater.clk.Now()
	since := now.Add(-updater.oldestIssuedSCT)
	serials, err := updater.getSerialsIssuedSince(since, batchSize)
	if err != nil {
		updater.log.AuditErr(fmt.Errorf("Failed to get certificate serials: %s", err))
		return
	}

	for _, serial := range serials {
		count, err := updater.getNumberOfReceipts(serial)
		if err != nil {
			updater.log.AuditErr(fmt.Errorf("Failed to get number of SCT receipts for certificate: %s", err))
			continue
		}
		if count == updater.numLogs {
			continue
		}
		cert, err := updater.sac.GetCertificate(serial)
		if err != nil {
			updater.log.AuditErr(fmt.Errorf("Failed to get certificate: %s", err))
			continue
		}

		err = updater.pubc.SubmitToCT(cert.DER)
		if err != nil {
			updater.log.AuditErr(fmt.Errorf("Failed to submit certificate to CT log: %s", err))
			continue
		}
	}

}

type looper struct {
	clk       clock.Clock
	stats     statsd.Statter
	batchSize int
	tickDur   time.Duration
	tickFunc  func(int)
	name      string
}

func (l *looper) loop() {
	for {
		tickStart := l.clk.Now()
		l.tickFunc(l.batchSize)
		l.stats.TimingDuration(fmt.Sprintf("OCSP.%s.TickDuration", l.name), time.Since(tickStart), 1.0)
		l.stats.Inc(fmt.Sprintf("OCSP.%s.Ticks", l.name), 1, 1.0)
		tickEnd := tickStart.Add(time.Since(tickStart))
		expectedTickEnd := tickStart.Add(l.tickDur)
		if tickEnd.After(expectedTickEnd) {
			l.stats.Inc(fmt.Sprintf("OCSP.%s.LongTicks", l.name), 1, 1.0)
		}
		// Sleep for the remaining tick period (if this is a negative number sleep
		// will not do anything and carry on)
		l.clk.Sleep(expectedTickEnd.Sub(tickEnd))
	}
}

func setupClients(c cmd.Config, stats statsd.Statter) (
	core.CertificateAuthority,
	core.Publisher,
	core.StorageAuthority,
	chan *amqp.Error,
) {
	ch, err := rpc.AmqpChannel(c)
	cmd.FailOnError(err, "Could not connect to AMQP")

	closeChan := ch.NotifyClose(make(chan *amqp.Error, 1))

	caRPC, err := rpc.NewAmqpRPCClient("OCSP->CA", c.AMQP.CA.Server, ch, stats)
	cmd.FailOnError(err, "Unable to create RPC client")

	cac, err := rpc.NewCertificateAuthorityClient(caRPC)
	cmd.FailOnError(err, "Unable to create CA client")

	pubRPC, err := rpc.NewAmqpRPCClient("OCSP->Publisher", c.AMQP.Publisher.Server, ch, stats)
	cmd.FailOnError(err, "Unable to create RPC client")

	pubc, err := rpc.NewPublisherClient(pubRPC)
	cmd.FailOnError(err, "Unable to create Publisher client")

	saRPC, err := rpc.NewAmqpRPCClient("OCSP->SA", c.AMQP.SA.Server, ch, stats)
	cmd.FailOnError(err, "Unable to create RPC client")

	sac, err := rpc.NewStorageAuthorityClient(saRPC)
	cmd.FailOnError(err, "Unable to create Publisher client")

	return cac, pubc, sac, closeChan
}

func main() {
	app := cmd.NewAppShell("ocsp-updater", "Generates and updates OCSP responses")

	app.Action = func(c cmd.Config) {
		// Set up logging
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")
		auditlogger.Info(app.VersionString())

		blog.SetAuditLogger(auditlogger)

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		go cmd.DebugServer(c.OCSPUpdater.DebugAddr)
		go cmd.ProfileCmd("OCSP-Updater", stats)

		// Configure DB
		dbMap, err := sa.NewDbMap(c.OCSPUpdater.DBConnect)
		cmd.FailOnError(err, "Could not connect to database")

		cac, pubc, sac, closeChan := setupClients(c, stats)

		updater, err := newUpdater(
			stats,
			clock.Default(),
			dbMap,
			cac,
			pubc,
			sac,
			// Necessary evil for now
			c.OCSPUpdater,
			len(c.Common.CT.Logs),
		)

		go updater.newCertificatesLoop.loop()
		go updater.oldOCSPResponsesLoop.loop()
		go updater.missingSCTReceiptsLoop.loop()

		cmd.FailOnError(err, "Failed to create updater")

		// TODO(): When the channel falls over so do we for now, if the AMQP channel
		// has already closed there is no real cleanup we can do. This is due to
		// really needing to change the underlying AMQP Server/Client reconnection
		// logic.
		err = <-closeChan
		auditlogger.AuditErr(fmt.Errorf(" [!] AMQP Channel closed, exiting: [%s]", err))
		os.Exit(1)
	}

	app.Run()
}
