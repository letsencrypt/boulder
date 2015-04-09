// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/streadway/amqp"
	// Load both drivers to allow configuring either
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"

	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
)

func main() {
	app := cmd.NewAppShell("boulder-ca")
	app.Action = func(c cmd.Config) {
		// Set up logging
		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag)
		cmd.FailOnError(err, "Could not connect to Syslog")

		cadb, err := ca.NewCertificateAuthorityDatabaseImpl(auditlogger, c.CA.DBDriver, c.CA.DBName)
		cmd.FailOnError(err, "Failed to create CA database")

		cai, err := ca.NewCertificateAuthorityImpl(auditlogger, c.CA.Server, c.CA.AuthKey, c.CA.Profile, cadb)
		cmd.FailOnError(err, "Failed to create CA impl")

		for {
			ch := cmd.AmqpChannel(c.AMQP.Server)
			closeChan := ch.NotifyClose(make(chan *amqp.Error, 1))

			sac, err := rpc.NewStorageAuthorityClient(c.AMQP.SA.Client, c.AMQP.SA.Client, ch)
			cmd.FailOnError(err, "Failed to create SA client")

			cai.SA = &sac

			cas, err := rpc.NewCertificateAuthorityServer(c.AMQP.CA.Server, ch, cai)
			cmd.FailOnError(err, "Unable to create CA server")

			cmd.RunUntilSignaled(auditlogger, cas, closeChan)
		}
	}

	app.Run()
}
