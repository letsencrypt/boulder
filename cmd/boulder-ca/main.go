// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
)

func main() {
	app := cmd.NewAppShell("boulder-ca")
	app.Action = func(c cmd.Config) {
		ch := cmd.AmqpChannel(c.AMQP.Server)

		// Set up logging
		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag)
		cmd.FailOnError(err, "Could not connect to Syslog")

		sac, err := rpc.NewStorageAuthorityClient(c.AMQP.SA.Client, c.AMQP.SA.Client, ch)
		cmd.FailOnError(err, "Failed to create SA client")

		cai, err := ca.NewCertificateAuthorityImpl(auditlogger, c.CA.Server, c.CA.AuthKey, c.CA.Profile)
		cmd.FailOnError(err, "Failed to create CA impl")

		cai.SA = &sac

		cas, err := rpc.NewCertificateAuthorityServer(c.AMQP.CA.Server, ch, cai)
		cmd.FailOnError(err, "Unable to create CA server")

		cmd.RunForever(cas)
	}

	app.Run()
}
