package main

import (
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/cdr"
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
		scoped := metrics.NewStatsdScope(stats, "VA", "DNS")
		sbc := newGoogleSafeBrowsing(c.VA.GoogleSafeBrowsing)
		var cdrClient *cdr.CAADistributedResolver
		if c.VA.CAADistributedResolver != nil {
			var err error
			cdrClient, err = cdr.New(
				scoped,
				c.VA.CAADistributedResolver.Timeout.Duration,
				c.VA.CAADistributedResolver.MaxFailures,
				c.VA.CAADistributedResolver.Proxies,
				logger,
			)
			cmd.FailOnError(err, "Failed to create CAADistributedResolver")
		}
		clk := clock.Default()
		vai := va.NewValidationAuthorityImpl(pc, sbc, caaClient, cdrClient, stats, clk)
		dnsTimeout, err := time.ParseDuration(c.Common.DNSTimeout)
		cmd.FailOnError(err, "Couldn't parse DNS timeout")
		dnsTries := c.VA.DNSTries
		if dnsTries < 1 {
			dnsTries = 1
		}
		if !c.Common.DNSAllowLoopbackAddresses {
			resolver := bdns.NewDNSResolverImpl(dnsTimeout, []string{c.Common.DNSResolver}, scoped, clk, dnsTries)
			resolver.LookupIPv6 = c.VA.LookupIPv6
			vai.DNSResolver = resolver

		} else {
			resolver := bdns.NewTestDNSResolverImpl(dnsTimeout, []string{c.Common.DNSResolver}, scoped, clk, dnsTries)
			resolver.LookupIPv6 = c.VA.LookupIPv6
			vai.DNSResolver = resolver
		}
		vai.UserAgent = c.VA.UserAgent

		vai.IssuerDomain = c.VA.IssuerDomain

		amqpConf := c.VA.AMQP

		vas, err := rpc.NewAmqpRPCServer(amqpConf, c.VA.MaxConcurrentRPCServerRequests, stats)
		cmd.FailOnError(err, "Unable to create VA RPC server")
		err = rpc.NewValidationAuthorityServer(vas, vai)
		cmd.FailOnError(err, "Unable to setup VA RPC server")

		err = vas.Start(amqpConf)
		cmd.FailOnError(err, "Unable to run VA RPC server")
	}

	app.Run()
}
