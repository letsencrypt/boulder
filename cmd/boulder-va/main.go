// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cmd"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/va"

	caaPB "github.com/letsencrypt/boulder/cmd/caa-checker/proto"
)

const clientName = "VA"

func main() {
	app := cmd.NewAppShell("boulder-va", "Handles challenge validation")
	app.Action = func(c cmd.Config, stats metrics.Statter, logger blog.Logger) {
		go cmd.DebugServer(c.VA.DebugAddr)

		go cmd.ProfileCmd("VA", stats)

		pc := &cmd.PortConfig{
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
		var caaClient caaPB.CAACheckerClient
		if c.VA.CAAService != nil {
			conn, err := bgrpc.ClientSetup(c.VA.CAAService)
			cmd.FailOnError(err, "Failed to load credentials and create connection to service")
			caaClient = caaPB.NewCAACheckerClient(conn)
		}
		clk := clock.Default()
		sbc := newGoogleSafeBrowsing(c.VA.GoogleSafeBrowsing)
		vai := va.NewValidationAuthorityImpl(pc, sbc, caaClient, stats, clk)
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
		err = rpc.NewValidationAuthorityServer(vas, vai)
		cmd.FailOnError(err, "Unable to setup VA RPC server")

		err = vas.Start(amqpConf)
		cmd.FailOnError(err, "Unable to run VA RPC server")
	}

	app.Run()
}
