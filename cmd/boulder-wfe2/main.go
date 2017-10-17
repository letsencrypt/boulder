package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/wfe2"
)

type config struct {
	WFE struct {
		cmd.ServiceConfig
		BaseURL          string
		ListenAddress    string
		TLSListenAddress string

		ServerCertificatePath string
		ServerKeyPath         string

		AllowOrigins []string

		CertCacheDuration           cmd.ConfigDuration
		CertNoCacheExpirationWindow cmd.ConfigDuration
		IndexCacheDuration          cmd.ConfigDuration
		IssuerCacheDuration         cmd.ConfigDuration

		ShutdownStopTimeout cmd.ConfigDuration

		SubscriberAgreementURL string

		AcceptRevocationReason bool
		AllowAuthzDeactivation bool

		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig

		Features map[string]bool
	}

	SubscriberAgreementURL string

	Syslog cmd.SyslogConfig

	Common struct {
		BaseURL    string
		IssuerCert string
	}
}

func setupWFE(c config, logger blog.Logger, stats metrics.Scope) (core.RegistrationAuthority, core.StorageAuthority) {
	var tls *tls.Config
	var err error
	if c.WFE.TLS.CertFile != nil {
		tls, err = c.WFE.TLS.Load()
		cmd.FailOnError(err, "TLS config")
	}

	raConn, err := bgrpc.ClientSetup(c.WFE.RAService, tls, stats)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA")
	rac := bgrpc.NewRegistrationAuthorityClient(rapb.NewRegistrationAuthorityClient(raConn))

	saConn, err := bgrpc.ClientSetup(c.WFE.SAService, tls, stats)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(saConn))

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

	err = features.Set(c.WFE.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.WFE.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	kp, err := goodkey.NewKeyPolicy("") // don't load any weak keys
	cmd.FailOnError(err, "Unable to create key policy")
	wfe, err := wfe2.NewWebFrontEndImpl(scope, cmd.Clock(), kp, logger)
	cmd.FailOnError(err, "Unable to create WFE")
	rac, sac := setupWFE(c, logger, scope)
	wfe.RA = rac
	wfe.SA = sac

	// TODO: remove this check once the production config uses the SubscriberAgreementURL in the wfe section
	if c.WFE.SubscriberAgreementURL != "" {
		wfe.SubscriberAgreementURL = c.WFE.SubscriberAgreementURL
	} else {
		wfe.SubscriberAgreementURL = c.SubscriberAgreementURL
	}

	wfe.AllowOrigins = c.WFE.AllowOrigins
	wfe.AcceptRevocationReason = c.WFE.AcceptRevocationReason
	wfe.AllowAuthzDeactivation = c.WFE.AllowAuthzDeactivation

	wfe.CertCacheDuration = c.WFE.CertCacheDuration.Duration
	wfe.CertNoCacheExpirationWindow = c.WFE.CertNoCacheExpirationWindow.Duration
	wfe.IndexCacheDuration = c.WFE.IndexCacheDuration.Duration
	wfe.IssuerCacheDuration = c.WFE.IssuerCacheDuration.Duration

	wfe.IssuerCert, err = cmd.LoadCert(c.Common.IssuerCert)
	cmd.FailOnError(err, fmt.Sprintf("Couldn't read issuer cert [%s]", c.Common.IssuerCert))

	logger.Info(fmt.Sprintf("WFE using key policy: %#v", kp))

	// Set up paths
	wfe.BaseURL = c.Common.BaseURL

	logger.Info(fmt.Sprintf("Server running, listening on %s...\n", c.WFE.ListenAddress))
	srv := &http.Server{
		Addr:    c.WFE.ListenAddress,
		Handler: wfe.Handler(),
	}

	go func() {
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			cmd.FailOnError(err, "Running HTTP server")
		}
	}()

	var tlsSrv *http.Server
	if c.WFE.TLSListenAddress != "" {
		tlsSrv = &http.Server{
			Addr:    c.WFE.TLSListenAddress,
			Handler: wfe.Handler(),
		}
		go func() {
			err := tlsSrv.ListenAndServeTLS(c.WFE.ServerCertificatePath, c.WFE.ServerKeyPath)
			cmd.FailOnError(err, "Error starting TLS server")
		}()
	}

	done := make(chan bool)
	go cmd.CatchSignals(logger, func() {
		ctx, cancel := context.WithTimeout(context.Background(), c.WFE.ShutdownStopTimeout.Duration)
		defer cancel()
		_ = srv.Shutdown(ctx)
		if tlsSrv != nil {
			_ = tlsSrv.Shutdown(ctx)
		}
		done <- true
	})

	// https://godoc.org/net/http#Server.Shutdown:
	// When Shutdown is called, Serve, ListenAndServe, and ListenAndServeTLS
	// immediately return ErrServerClosed. Make sure the program doesn't exit and
	// waits instead for Shutdown to return.
	<-done
}
