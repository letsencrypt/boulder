// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/cactus/go-statsd-client/statsd"
	"github.com/codegangsta/cli"
	"gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

type mailer struct {
	stats statsd.Statter
	log   *blog.AuditLogger
	dbMap *gorp.DbMap
}

func (m *mailer) findExpiringCertificates(warningDays []int) error {
	var err error
	for _, expiresIn := range warningDays {
		left := time.Now().Add(time.Hour * 24 * time.Duration(expiresIn))
		right := left.Add(time.Hour * 24)

		var certs []core.Certificate
		_, err := m.dbMap.Select(
			&certs,
			`SELECT cert.* FROM certificates AS certs JOIN certificateStatus AS cs on cs.serial = cert.serial
       WHERE cert.expires > :cutoff-a AND cert.Expires < :cutoff-b AND cs.status != "revoked"
       ORDER BY cert.Issued ASC`,
			map[string]interface{}{
				"cutoff-a": left,
				"cutoff-b": right,
			},
		)
		if err == sql.ErrNoRows {
			m.log.Info("All up to date. No expiration emails needed.")
		} else if err != nil {
			m.log.Err(fmt.Sprintf("Error loading certificates: %s", err))
		} else {
			// Do things...
			// cert expires in expiresIn, send email to registration contacts
			for _, cert := range certs {
				reg, err := m.dbMap.Get(&core.Registration{}, cert.RegistrationID)
				if err != nil {
					return err
				}

				m.sendWarning(cert, reg, expiresIn)
			}
		}
	}

	return err
}

func (m *mailer) sendWarning(cert core.Certificate, reg core.Registration, expiresIn int) {

}

func main() {
	app := cmd.NewAppShell("expiration-mailer")

	app.App.Flags = append(app.App.Flags, cli.IntFlag{
		Name:   "limit",
		Value:  emailLimit,
		EnvVar: "EMAIL_LIMIT",
		Usage:  "Maximum number of emails to send per run",
	})

	app.Config = func(c *cli.Context, config cmd.Config) cmd.Config {
		config.Mailer.Limit = c.GlobalInt("emailLimit")
		return config
	}

	app.Action = func(c cmd.Config) {
		auditlogger.Info(app.VersionString())

		// Set up logging
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.Mailer.DebugAddr)

		// Configure DB
		dbMap, err := sa.NewDbMap(c.Mailer.DBDriver, c.Mailer.DBConnect)
		cmd.FailOnError(err, "Could not connect to database")

		err = findExpiringCertificates()
		if err != nil {
			auditlogger.WarningErr(err)
		}
	}
}
