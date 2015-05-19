// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"net/http"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/wfe"

	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
)

func setupClients(c cmd.Config) (cac rpc.CertificateAuthorityClient, dbMap gorp.DbMap, chan *amqp.Error) {
	ch := cmd.AmqpChannel(c.AMQP.Server)
	closeChan := ch.NotifyClose(make(chan *amqp.Error, 1))

	cac, err := rpc.NewCertificateAuthorityClient(c.AMQP.CA.Client, c.AMQP.CA.Server, ch)
	cmd.FailOnError(err, "Unable to create CA client")

	db, err := sql.Open("sqlite3", ":memory:")
	dbmap := &gorp.DbMap{
		Db: db,
		Dialect: gorp.SqliteDialect{},
		//Dialect: gorp.MySQLDialect{Engine: "InnoDB", Encoding: "UTF8"},
		TypeConverter: core.BoulderTypeConverter{}
	}
	return cac, dbMap, closeChan
}

func updateOne(dbMap gorp.DbMap) {
	tx, err := ssa.dbMap.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}

	// If there are fewer than this many days left before the currently-signed
	// OCSP response expires, sign a new OCSP response.
	minDaysToExpiry := 3
	var certificateStatus []core.CertificateStatus
	result, err = tx.Select(&certificateStatus,
		`SELECT * FROM certificateStatus
		 WHERE ocspLastUpdated > ?
		 ORDER BY ocspLastUpdated ASC
		 LIMIT 1`, time.Now().Add(-minDaysToExpiry * 24 * time.Hour))
	if err == sql.ErrNoRows {
		return
	} else if err != nil {
		blog.GetAuditLogger().Error("Error getting certificate status: " + err.Error())
	} else {
		fmt.Println(result)
	}
}

func main() {
	app := cmd.NewAppShell("ocsp-updater")
	app.Action = func(c cmd.Config) {
		// Set up logging
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		blog.SetAuditLogger(auditlogger)

		cac, dbMap, closeChan := setupClients(c)

		go func() {
			// sit around and reconnect to AMQP if the channel
			// drops for some reason and repopulate the wfe object
			// with new RA and SA rpc clients.
			for {
				for err := range closeChan {
					auditlogger.Warning(fmt.Sprintf("AMQP Channel closed, will reconnect in 5 seconds: [%s]", err))
					time.Sleep(time.Second * 5)
					cac, dbMap, closeChan = setupClients(c)
					wfe.RA = &rac
					wfe.SA = &sac
					auditlogger.Warning("Reconnected to AMQP")
				}
			}
		}()

		updateOne()
	}

	app.Run()
}
