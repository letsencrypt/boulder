package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

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

		CertCacheDuration           string
		CertNoCacheExpirationWindow string
		IndexCacheDuration          string
		IssuerCacheDuration         string

		ShutdownStopTimeout string
		ShutdownKillTimeout string

		SubscriberAgreementURL string
	}

	*cmd.AllowedSigningAlgos

	cmd.StatsdConfig

	cmd.SyslogConfig

	SubscriberAgreementURL string

	Common struct {
		BaseURL string
		// Path to a PEM-encoded copy of the issuer certificate.
		IssuerCert string
	}
}

func (cfg config) KeyPolicy() goodkey.KeyPolicy {
	if cfg.AllowedSigningAlgos != nil {
		return goodkey.KeyPolicy{
			AllowRSA:           cfg.AllowedSigningAlgos.RSA,
			AllowECDSANISTP256: cfg.AllowedSigningAlgos.ECDSANISTP256,
			AllowECDSANISTP384: cfg.AllowedSigningAlgos.ECDSANISTP384,
			AllowECDSANISTP521: cfg.AllowedSigningAlgos.ECDSANISTP521,
		}
	}
	return goodkey.KeyPolicy{
		AllowRSA: true,
	}
}

func setupWFE(cfg config, logger blog.Logger, stats metrics.Statter) (*rpc.RegistrationAuthorityClient, *rpc.StorageAuthorityClient) {
	amqpConf := cfg.WFE.AMQP
	rac, err := rpc.NewRegistrationAuthorityClient(clientName, amqpConf, stats)
	cmd.FailOnError(err, "Unable to create RA client")

	sac, err := rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
	cmd.FailOnError(err, "Unable to create SA client")

	return rac, sac
}

func main() {
	configFile := flag.String("config", "", "Mandatory file containing a JSON config.")
	listenAddr := flag.String("addr", "", "Overrides the listenAddr setting in WFE config")

	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}
	var cfg config
	cmd.ReadJSONFile(*configFile, &cfg)

	if *listenAddr != "" {
		cfg.WFE.ListenAddress = *listenAddr
	}

	if os.Getenv("WFE_LISTEN_ADDR") != "" {
		cfg.WFE.ListenAddress = os.Getenv("WFE_LISTEN_ADDR")
	}

	stats, logger := cmd.StatsAndLogging(cfg.StatsdConfig, cfg.SyslogConfig)

	go cmd.DebugServer(cfg.WFE.DebugAddr)

	wfe, err := wfe.NewWebFrontEndImpl(stats, clock.Default(), cfg.KeyPolicy(), logger)
	cmd.FailOnError(err, "Unable to create WFE")
	rac, sac := setupWFE(cfg, logger, stats)
	wfe.RA = rac
	wfe.SA = sac

	// TODO: remove this check once the production config uses the SubscriberAgreementURL in the wfe section
	if cfg.WFE.SubscriberAgreementURL != "" {
		wfe.SubscriberAgreementURL = cfg.WFE.SubscriberAgreementURL
	} else {
		wfe.SubscriberAgreementURL = cfg.SubscriberAgreementURL
	}

	wfe.AllowOrigins = cfg.WFE.AllowOrigins

	wfe.CertCacheDuration, err = time.ParseDuration(cfg.WFE.CertCacheDuration)
	cmd.FailOnError(err, "Couldn't parse certificate caching duration")
	wfe.CertNoCacheExpirationWindow, err = time.ParseDuration(cfg.WFE.CertNoCacheExpirationWindow)
	cmd.FailOnError(err, "Couldn't parse certificate expiration no-cache window")
	wfe.IndexCacheDuration, err = time.ParseDuration(cfg.WFE.IndexCacheDuration)
	cmd.FailOnError(err, "Couldn't parse index caching duration")
	wfe.IssuerCacheDuration, err = time.ParseDuration(cfg.WFE.IssuerCacheDuration)
	cmd.FailOnError(err, "Couldn't parse issuer caching duration")

	wfe.ShutdownStopTimeout, err = time.ParseDuration(cfg.WFE.ShutdownStopTimeout)
	cmd.FailOnError(err, "Couldn't parse shutdown stop timeout")
	wfe.ShutdownKillTimeout, err = time.ParseDuration(cfg.WFE.ShutdownKillTimeout)
	cmd.FailOnError(err, "Couldn't parse shutdown kill timeout")

	wfe.IssuerCert, err = cmd.LoadCert(cfg.Common.IssuerCert)
	cmd.FailOnError(err, fmt.Sprintf("Couldn't read issuer cert [%s]", cfg.Common.IssuerCert))

	logger.Info(fmt.Sprintf("WFE using key policy: %#v", cfg.KeyPolicy()))

	go cmd.ProfileCmd("WFE", stats)

	// Set up paths
	wfe.BaseURL = cfg.Common.BaseURL
	h, err := wfe.Handler()
	cmd.FailOnError(err, "Problem setting up HTTP handlers")

	httpMonitor := metrics.NewHTTPMonitor(stats, h, "WFE")

	logger.Info(fmt.Sprintf("Server running, listening on %s...\n", cfg.WFE.ListenAddress))
	srv := &http.Server{
		Addr:    cfg.WFE.ListenAddress,
		Handler: httpMonitor,
	}

	hd := &httpdown.HTTP{
		StopTimeout: wfe.ShutdownStopTimeout,
		KillTimeout: wfe.ShutdownKillTimeout,
		Stats:       metrics.NewFBAdapter(stats, "WFE", clock.Default()),
	}
	err = httpdown.ListenAndServe(srv, hd)
	cmd.FailOnError(err, "Error starting HTTP server")
}
