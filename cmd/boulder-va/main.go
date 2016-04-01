// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/va"
)

const clientName = "VA"

func main() {
	app := cmd.NewAppShell("boulder-va", "Handles challenge validation")
	app.Action = func(c cmd.Config, stats metrics.Statter, auditlogger *blog.AuditLogger) {
		go cmd.DebugServer(c.VA.DebugAddr)

		go cmd.ProfileCmd("VA", stats)

		pc := &va.PortConfig{
			HTTPPort:  80,
			HTTPSPort: 443,
			TLSPort:   443,
		}
		if c.VA.PortConfig.HTTPPort != 0 {
			pc.HTTPPort = c.VA.PortConfig.HTTPPort
		}
		if c.VA.PortConfig.HTTPSPort != 0 {
			pc.HTTPSPort = c.VA.PortConfig.HTTPSPort
		}
		if c.VA.PortConfig.TLSPort != 0 {
			pc.TLSPort = c.VA.PortConfig.TLSPort
		}
		clk := clock.Default()
		sbc := newGoogleSafeBrowsing(c.VA.GoogleSafeBrowsing)
		vai := va.NewValidationAuthorityImpl(pc, sbc, stats, clk)
		dnsTimeout, err := time.ParseDuration(c.Common.DNSTimeout)
		cmd.FailOnError(err, "Couldn't parse DNS timeout")
		scoped := metrics.NewStatsdScope(stats, "VA", "DNS")
		dnsTries := c.VA.DNSTries
		if dnsTries < 1 {
			dnsTries = 1
		}
		if !c.Common.DNSAllowLoopbackAddresses {
			vai.DNSResolver = bdns.NewDNSResolverImpl(dnsTimeout, []string{c.Common.DNSResolver}, scoped, clk, dnsTries)
		} else {
			vai.DNSResolver = bdns.NewTestDNSResolverImpl(dnsTimeout, []string{c.Common.DNSResolver}, scoped, clk, dnsTries)
		}
		vai.UserAgent = c.VA.UserAgent
		vai.IssuerDomain = c.VA.IssuerDomain

		amqpConf := c.VA.AMQP
		rac, err := rpc.NewRegistrationAuthorityClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Unable to create RA client")

		vai.RA = rac

		vas, err := rpc.NewAmqpRPCServer(amqpConf, c.VA.MaxConcurrentRPCServerRequests, stats)
		cmd.FailOnError(err, "Unable to create VA RPC server")
		rpc.NewValidationAuthorityServer(vas, vai)

		err = vas.Start(amqpConf)
		cmd.FailOnError(err, "Unable to run VA RPC server")
	}

	app.Run()
}
