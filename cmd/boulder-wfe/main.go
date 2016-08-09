package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/facebookgo/httpdown"
	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/goodkey"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/wfe"
)

const clientName = "WFE"

type config struct {
	WFE struct {
		cmd.ServiceConfig
		BaseURL       string
		ListenAddress string

		AllowOrigins []string

		CertCacheDuration           cmd.ConfigDuration
		CertNoCacheExpirationWindow cmd.ConfigDuration
		IndexCacheDuration          cmd.ConfigDuration
		IssuerCacheDuration         cmd.ConfigDuration

		ShutdownStopTimeout cmd.ConfigDuration
		ShutdownKillTimeout cmd.ConfigDuration

		SubscriberAgreementURL string

		CheckMalformedCSR      bool
		AcceptRevocationReason bool
	}

	Statsd cmd.StatsdConfig

	SubscriberAgreementURL string

	Syslog cmd.SyslogConfig

	Common struct {
		BaseURL    string
		IssuerCert string
	}
}

func setupWFE(c config, logger blog.Logger, stats metrics.Statter) (*rpc.RegistrationAuthorityClient, *rpc.StorageAuthorityClient) {
	amqpConf := c.WFE.AMQP
	rac, err := rpc.NewRegistrationAuthorityClient(clientName, amqpConf, stats)
	cmd.FailOnError(err, "Unable to create RA client")

	sac, err := rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
	cmd.FailOnError(err, "Unable to create SA client")

	return rac, sac
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	go cmd.DebugServer(c.WFE.DebugAddr)

	stats, logger := cmd.StatsAndLogging(c.Statsd, c.Syslog)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString(clientName))

	wfe, err := wfe.NewWebFrontEndImpl(stats, clock.Default(), goodkey.NewKeyPolicy(), logger)
	cmd.FailOnError(err, "Unable to create WFE")
	rac, sac := setupWFE(c, logger, stats)
	wfe.RA = rac
	wfe.SA = sac

	// TODO: remove this check once the production config uses the SubscriberAgreementURL in the wfe section
	if c.WFE.SubscriberAgreementURL != "" {
		wfe.SubscriberAgreementURL = c.WFE.SubscriberAgreementURL
	} else {
		wfe.SubscriberAgreementURL = c.SubscriberAgreementURL
	}

	wfe.AllowOrigins = c.WFE.AllowOrigins
	wfe.CheckMalformedCSR = c.WFE.CheckMalformedCSR
	wfe.AcceptRevocationReason = c.WFE.AcceptRevocationReason

	wfe.CertCacheDuration = c.WFE.CertCacheDuration.Duration
	wfe.CertNoCacheExpirationWindow = c.WFE.CertNoCacheExpirationWindow.Duration
	wfe.IndexCacheDuration = c.WFE.IndexCacheDuration.Duration
	wfe.IssuerCacheDuration = c.WFE.IssuerCacheDuration.Duration

	wfe.IssuerCert, err = cmd.LoadCert(c.Common.IssuerCert)
	cmd.FailOnError(err, fmt.Sprintf("Couldn't read issuer cert [%s]", c.Common.IssuerCert))

	logger.Info(fmt.Sprintf("WFE using key policy: %#v", goodkey.NewKeyPolicy()))

	go cmd.ProfileCmd("WFE", stats)

	// Set up paths
	wfe.BaseURL = c.Common.BaseURL
	h, err := wfe.Handler()
	cmd.FailOnError(err, "Problem setting up HTTP handlers")

	httpMonitor := metrics.NewHTTPMonitor(stats, h, "WFE")

	logger.Info(fmt.Sprintf("Server running, listening on %s...\n", c.WFE.ListenAddress))
	srv := &http.Server{
		Addr:    c.WFE.ListenAddress,
		Handler: httpMonitor,
	}

	hd := &httpdown.HTTP{
		StopTimeout: c.WFE.ShutdownStopTimeout.Duration,
		KillTimeout: c.WFE.ShutdownKillTimeout.Duration,
		Stats:       metrics.NewFBAdapter(stats, "WFE", clock.Default()),
	}
	err = httpdown.ListenAndServe(srv, hd)
	cmd.FailOnError(err, "Error starting HTTP server")
}
