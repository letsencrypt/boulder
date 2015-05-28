// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/x509"
	"database/sql"
	"fmt"
	"math"
	"time"

	// Load both drivers to allow configuring either
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"

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

const ocspResponseLimit int = 128

func setupClients(c cmd.Config) (rpc.CertificateAuthorityClient, chan *amqp.Error) {
	ch := cmd.AmqpChannel(c.AMQP.Server)
	closeChan := ch.NotifyClose(make(chan *amqp.Error, 1))

	cac, err := rpc.NewCertificateAuthorityClient("OCSP->CA", c.AMQP.CA.Server, ch)
	cmd.FailOnError(err, "Unable to create CA client")

	return cac, closeChan
}

func processResponse(cac rpc.CertificateAuthorityClient, tx *gorp.Transaction, serial string) error {
	certObj, err := tx.Get(core.Certificate{}, serial)
	if err != nil {
		return err
	}
	statusObj, err := tx.Get(core.CertificateStatus{}, serial)
	if err != nil {
		return err
	}

	cert := certObj.(*core.Certificate)
	status := statusObj.(*core.CertificateStatus)

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

	ocspResponse, err := cac.GenerateOCSP(signRequest)
	if err != nil {
		return err
	}

	timeStamp := time.Now()

	// Record the response.
	ocspResp := &core.OcspResponse{Serial: serial, CreatedAt: timeStamp, Response: ocspResponse}
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

func findStaleResponses(cac rpc.CertificateAuthorityClient, dbMap *gorp.DbMap, oldestLastUpdatedTime time.Time, responseLimit int) error {
	log := blog.GetAuditLogger()

	// If there are fewer than this many days left before the currently-signed
	// OCSP response expires, sign a new OCSP response.
	var certificateStatus []core.CertificateStatus
	_, err := dbMap.Select(&certificateStatus,
		`SELECT cs.* FROM certificateStatus AS cs
		 WHERE cs.ocspLastUpdated < ?
		 ORDER BY cs.ocspLastUpdated ASC
		 LIMIT ?`, oldestLastUpdatedTime, responseLimit)

	if err == sql.ErrNoRows {
		log.Info("All up to date. No OCSP responses needed.")
	} else if err != nil {
		log.Err(fmt.Sprintf("Error loading certificate status: %s", err))
	} else {
		log.Info(fmt.Sprintf("Processing OCSP Responses...\n"))
		for i, status := range certificateStatus {
			log.Info(fmt.Sprintf("OCSP %d: %s", i, status.Serial))

			// Each response gets a transaction. To speed this up, we can batch
			// transactions.
			tx, err := dbMap.Begin()
			if err != nil {
				log.Err(fmt.Sprintf("Error starting transaction, aborting: %s", err))
				tx.Rollback()
				return err
			}

			if err := processResponse(cac, tx, status.Serial); err != nil {
				log.Err(fmt.Sprintf("Could not process OCSP Response for %s: %s", status.Serial, err))
				tx.Rollback()
			} else {
				log.Info(fmt.Sprintf("OCSP %d: %s OK", i, status.Serial))
				tx.Commit()
			}
		}
	}

	return err
}

func main() {
	app := cmd.NewAppShell("ocsp-updater")

	app.App.Flags = append(app.App.Flags, cli.IntFlag{
		Name:   "limit",
		Value:  ocspResponseLimit,
		EnvVar: "OCSP_LIMIT",
		Usage:  "Count of responses to process per run",
	})

	app.Config = func(c *cli.Context, config cmd.Config) cmd.Config {
		config.OCSP.ResponseLimit = c.GlobalInt("limit")
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

		// Configure DB
		dbMap, err := sa.NewDbMap(c.OCSP.DBDriver, c.OCSP.DBName)
		cmd.FailOnError(err, "Could not connect to database")

		dbMap.AddTableWithName(core.OcspResponse{}, "ocspResponses").SetKeys(true, "ID")
		dbMap.AddTableWithName(core.Certificate{}, "certificates").SetKeys(false, "Serial")
		dbMap.AddTableWithName(core.CertificateStatus{}, "certificateStatus").SetKeys(false, "Serial").SetVersionCol("LockCol")

		cac, closeChan := setupClients(c)

		go func() {
			// Abort if we disconnect from AMQP
			for {
				for err := range closeChan {
					auditlogger.Warning(fmt.Sprintf("AMQP Channel closed, aborting early: [%s]", err))
					panic(err)
				}
			}
		}()

		auditlogger.Info(app.VersionString())

		// Calculate the cut-off timestamp
		dur, err := time.ParseDuration(c.OCSP.MinTimeToExpiry)
		cmd.FailOnError(err, "Could not parse MinTimeToExpiry from config.")

		oldestLastUpdatedTime := time.Now().Add(-dur)
		auditlogger.Info(fmt.Sprintf("Searching for OCSP reponses older than %s", oldestLastUpdatedTime))

		count := int(math.Min(float64(ocspResponseLimit), float64(c.OCSP.ResponseLimit)))

		err = findStaleResponses(cac, dbMap, oldestLastUpdatedTime, count)
		if err != nil {
			auditlogger.WarningErr(err)
		}
	}

	app.Run()
}
