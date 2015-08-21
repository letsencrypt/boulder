// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/x509"
	"database/sql"
	"fmt"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

// FatalError indicates the updater should stop execution
type FatalError string

func (e FatalError) Error() string { return string(e) }

// OCSPUpdater contains the useful objects for the Updater
type OCSPUpdater struct {
	stats statsd.Statter
	log   *blog.AuditLogger
	cac   rpc.CertificateAuthorityClient
	dbMap *gorp.DbMap
}

func setupClients(c cmd.Config) (rpc.CertificateAuthorityClient, chan *amqp.Error) {
	ch, err := rpc.AmqpChannel(c)
	cmd.FailOnError(err, "Could not connect to AMQP")

	closeChan := ch.NotifyClose(make(chan *amqp.Error, 1))

	caRPC, err := rpc.NewAmqpRPCClient("OCSP->CA", c.AMQP.CA.Server, ch)
	cmd.FailOnError(err, "Unable to create RPC client")

	cac, err := rpc.NewCertificateAuthorityClient(caRPC)
	cmd.FailOnError(err, "Unable to create CA client")

	return cac, closeChan
}

func (updater *OCSPUpdater) processResponse(tx *gorp.Transaction, serial string) error {
	certObj, err := tx.Get(core.Certificate{}, serial)
	if err != nil {
		return err
	}
	statusObj, err := tx.Get(core.CertificateStatus{}, serial)
	if err != nil {
		return err
	}

	cert, ok := certObj.(*core.Certificate)
	if !ok {
		return fmt.Errorf("Cast failure")
	}
	status, ok := statusObj.(*core.CertificateStatus)
	if !ok {
		return fmt.Errorf("Cast failure")
	}

	_, err = x509.ParseCertificate(cert.DER)
	if err != nil {
		return err
	}

	signRequest := core.OCSPSigningRequest{
		CertDER:   cert.DER,
		Reason:    status.RevokedReason,
		Status:    string(status.Status),
		RevokedAt: status.RevokedDate,
	}

	ocspResponse, err := updater.cac.GenerateOCSP(signRequest)
	if err != nil {
		return err
	}

	timeStamp := time.Now()

	// Record the response.
	ocspResp := &core.OCSPResponse{Serial: serial, CreatedAt: timeStamp, Response: ocspResponse}
	err = tx.Insert(ocspResp)
	if err != nil {
		return err
	}

	// Reset the update clock
	status.OCSPLastUpdated = timeStamp
	_, err = tx.Update(status)
	if err != nil {
		return err
	}

	// Done
	return nil
}

// Produce one OCSP response for the given serial, returning err
// if anything went wrong. This method will open and commit a transaction.
func (updater *OCSPUpdater) updateOneSerial(serial string) error {
	innerStart := time.Now()
	// Each response gets a transaction. In the future we can increase
	// performance by batching transactions.
	// The key thing to think through is the cost of rollbacks, and whether
	// we should rollback if CA/HSM fails to sign the response or only
	// upon a partial DB insert.
	tx, err := updater.dbMap.Begin()
	if err != nil {
		updater.log.Err(fmt.Sprintf("OCSP %s: Error starting transaction, aborting: %s", serial, err))
		updater.stats.Inc("OCSP.UpdatesFailed", 1, 1.0)
		tx.Rollback()
		// Failure to begin transaction is a fatal error.
		return FatalError(err.Error())
	}

	if err := updater.processResponse(tx, serial); err != nil {
		updater.log.Err(fmt.Sprintf("OCSP %s: Could not process OCSP Response, skipping: %s", serial, err))
		updater.stats.Inc("OCSP.UpdatesFailed", 1, 1.0)
		tx.Rollback()
		return err
	}

	err = tx.Commit()
	if err != nil {
		updater.log.Err(fmt.Sprintf("OCSP %s: Error committing transaction, skipping: %s", serial, err))
		updater.stats.Inc("OCSP.UpdatesFailed", 1, 1.0)
		tx.Rollback()
		return err
	}

	updater.log.Info(fmt.Sprintf("OCSP %s: OK", serial))
	updater.stats.Inc("OCSP.UpdatesProcessed", 1, 1.0)
	updater.stats.TimingDuration("OCSP.UpdateTime", time.Since(innerStart), 1.0)
	return nil
}

// findStaleResponses opens a transaction and processes up to responseLimit
// responses in a single batch. The responseLimit should be relatively small,
// so as to limit the chance of the transaction failing due to concurrent
// updates.
func (updater *OCSPUpdater) findStaleResponses(oldestLastUpdatedTime time.Time, responseLimit int) error {
	var certificateStatus []core.CertificateStatus
	_, err := updater.dbMap.Select(&certificateStatus,
		`SELECT cs.* FROM certificateStatus AS cs JOIN certificates AS cert ON cs.serial = cert.serial
		 WHERE cs.ocspLastUpdated < ? AND cert.expires > now()
		 ORDER BY cs.ocspLastUpdated ASC
		 LIMIT ?`, oldestLastUpdatedTime, responseLimit)

	if err == sql.ErrNoRows {
		updater.log.Info("All up to date. No OCSP responses needed.")
	} else if err != nil {
		updater.log.Err(fmt.Sprintf("Error loading certificate status: %s", err))
	} else {
		updater.log.Info(fmt.Sprintf("Processing OCSP Responses...\n"))
		outerStart := time.Now()

		for i, status := range certificateStatus {
			updater.log.Debug(fmt.Sprintf("OCSP %s: (%d/%d)", status.Serial, i, responseLimit))

			err = updater.updateOneSerial(status.Serial)
			// Abort if we recieve a fatal error
			if _, ok := err.(FatalError); ok {
				return err
			}
		}

		updater.stats.TimingDuration("OCSP.BatchTime", time.Since(outerStart), 1.0)
		updater.stats.Inc("OCSP.BatchesProcessed", 1, 1.0)
	}

	return err
}

func main() {
	app := cmd.NewAppShell("ocsp-updater")

	app.App.Flags = append(app.App.Flags, cli.IntFlag{
		Name:   "limit",
		Value:  100,
		EnvVar: "OCSP_LIMIT",
		Usage:  "Count of responses to process per run",
	})

	app.Config = func(c *cli.Context, config cmd.Config) cmd.Config {
		config.OCSPUpdater.ResponseLimit = c.GlobalInt("limit")
		return config
	}

	app.Action = func(c cmd.Config) {
		// Set up logging
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.OCSPUpdater.DebugAddr)

		// Configure DB
		dbMap, err := sa.NewDbMap(c.OCSPUpdater.DBConnect)
		cmd.FailOnError(err, "Could not connect to database")

		cac, closeChan := setupClients(c)

		go func() {
			// Abort if we disconnect from AMQP
			for {
				for err := range closeChan {
					auditlogger.Warning(fmt.Sprintf(" [!] AMQP Channel closed, aborting early: [%s]", err))
					panic(err)
				}
			}
		}()

		auditlogger.Info(app.VersionString())

		updater := &OCSPUpdater{
			cac:   cac,
			dbMap: dbMap,
			stats: stats,
			log:   auditlogger,
		}

		// Calculate the cut-off timestamp
		if c.OCSPUpdater.MinTimeToExpiry == "" {
			panic("Config must specify a MinTimeToExpiry period.")
		}
		dur, err := time.ParseDuration(c.OCSPUpdater.MinTimeToExpiry)
		cmd.FailOnError(err, "Could not parse MinTimeToExpiry from config.")

		oldestLastUpdatedTime := time.Now().Add(-dur)
		auditlogger.Info(fmt.Sprintf("Searching for OCSP responses older than %s", oldestLastUpdatedTime))

		// When we choose to batch responses, it may be best to restrict count here,
		// change the transaction to survive the whole findStaleResponses, and to
		// loop this method call however many times is appropriate.
		err = updater.findStaleResponses(oldestLastUpdatedTime, c.OCSPUpdater.ResponseLimit)
		if err != nil {
			auditlogger.WarningErr(err)
		}
	}

	app.Run()
}
