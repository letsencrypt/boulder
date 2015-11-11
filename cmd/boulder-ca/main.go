// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

func main() {
	app := cmd.NewAppShell("boulder-ca", "Handles issuance operations")
	app.Action = func(c cmd.Config, stats statsd.Statter, auditlogger *blog.AuditLogger) {
		// Validate PA config and set defaults if needed
		cmd.FailOnError(c.PA.CheckChallenges(), "Invalid PA configuration")
		c.PA.SetDefaultChallengesIfEmpty()

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		go cmd.DebugServer(c.CA.DebugAddr)

		paDbMap, err := sa.NewDbMap(c.PA.DBConnect)
		cmd.FailOnError(err, "Couldn't connect to policy database")
		pa, err := policy.NewPolicyAuthorityImpl(paDbMap, c.PA.EnforcePolicyWhitelist, c.PA.Challenges)
		cmd.FailOnError(err, "Couldn't create PA")

		cai, err := ca.NewCertificateAuthorityImpl(c.CA, clock.Default(), stats, c.Common.IssuerCert)
		cmd.FailOnError(err, "Failed to create CA impl")
		cai.PA = pa

		go cmd.ProfileCmd("CA", stats)

		saRPC, err := rpc.NewAmqpRPCClient("CA->SA", c.AMQP.SA.Server, c, stats)
		cmd.FailOnError(err, "Unable to create RPC client")

		sac, err := rpc.NewStorageAuthorityClient(saRPC)
		cmd.FailOnError(err, "Failed to create SA client")

		pubRPC, err := rpc.NewAmqpRPCClient("CA->Publisher", c.AMQP.Publisher.Server, c, stats)
		cmd.FailOnError(err, "Unable to create RPC client")

		pubc, err := rpc.NewPublisherClient(pubRPC)
		cmd.FailOnError(err, "Failed to create Publisher client")

		cai.Publisher = &pubc
		cai.SA = &sac

		cas, err := rpc.NewAmqpRPCServer(c.AMQP.CA.Server, c.CA.MaxConcurrentRPCServerRequests, c)
		cmd.FailOnError(err, "Unable to create CA RPC server")
		rpc.NewCertificateAuthorityServer(cas, cai)

		err = cas.Start(c)
		cmd.FailOnError(err, "Unable to run CA RPC server")
	}

	app.Run()
}
