// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"os"

	ct "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/google/certificate-transparency/go"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/publisher"
	"github.com/letsencrypt/boulder/rpc"
)

const clientName = "Publisher"

func main() {
	app := cmd.NewAppShell("boulder-publisher", "Submits issued certificates to CT logs")
	app.Action = func(c cmd.Config, stats metrics.Statter, auditlogger *blog.AuditLogger) {
		logs := make([]*publisher.Log, len(c.Common.CT.Logs))
		var err error
		for i, ld := range c.Common.CT.Logs {
			logs[i], err = publisher.NewLog(ld.URI, ld.Key)
			cmd.FailOnError(err, "Unable to parse CT log description")
		}

		if c.Common.CT.IntermediateBundleFilename == "" {
			auditlogger.Err("No CT submission bundle provided")
			os.Exit(1)
		}
		pemBundle, err := core.LoadCertBundle(c.Common.CT.IntermediateBundleFilename)
		cmd.FailOnError(err, "Failed to load CT submission bundle")
		bundle := []ct.ASN1Cert{}
		for _, cert := range pemBundle {
			bundle = append(bundle, ct.ASN1Cert(cert.Raw))
		}

		pubi := publisher.New(bundle, logs, c.Publisher.SubmissionTimeout.Duration)

		go cmd.DebugServer(c.Publisher.DebugAddr)
		go cmd.ProfileCmd("Publisher", stats)

		amqpConf := c.Publisher.AMQP
		pubi.SA, err = rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Unable to create SA client")

		pubs, err := rpc.NewAmqpRPCServer(amqpConf, c.Publisher.MaxConcurrentRPCServerRequests, stats)
		cmd.FailOnError(err, "Unable to create Publisher RPC server")
		rpc.NewPublisherServer(pubs, pubi)

		err = pubs.Start(amqpConf)
		cmd.FailOnError(err, "Unable to run Publisher RPC server")
	}

	app.Run()
}
