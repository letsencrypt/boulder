package main

import (
	"context"
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
	"github.com/letsencrypt/boulder/wfe"
)

type config struct {
	WFE struct {
		cmd.ServiceConfig
		ListenAddress    string
		TLSListenAddress string

		ServerCertificatePath string
		ServerKeyPath         string

		AllowOrigins []string

		ShutdownStopTimeout cmd.ConfigDuration

		SubscriberAgreementURL string

		AcceptRevocationReason bool
		AllowAuthzDeactivation bool

		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig

		Features map[string]bool

		// DirectoryCAAIdentity is used for the /directory response's "meta"
		// element's "caaIdentities" field. It should match the VA's "issuerDomain"
		// configuration value (this value is the one used to enforce CAA)
		DirectoryCAAIdentity string
		// DirectoryWebsite is used for the /directory response's "meta" element's
		// "website" field.
		DirectoryWebsite string
	}

	Syslog cmd.SyslogConfig

	Common struct {
		IssuerCert string
	}
}

func setupWFE(c config, logger blog.Logger, stats metrics.Scope) (core.RegistrationAuthority, core.StorageAuthority) {
	tlsConfig, err := c.WFE.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clientMetrics := bgrpc.NewClientMetrics(stats)
	raConn, err := bgrpc.ClientSetup(c.WFE.RAService, tlsConfig, clientMetrics)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA")
	rac := bgrpc.NewRegistrationAuthorityClient(rapb.NewRegistrationAuthorityClient(raConn))

	saConn, err := bgrpc.ClientSetup(c.WFE.SAService, tlsConfig, clientMetrics)
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
	wfe, err := wfe.NewWebFrontEndImpl(scope, cmd.Clock(), kp, logger)
	cmd.FailOnError(err, "Unable to create WFE")
	rac, sac := setupWFE(c, logger, scope)
	wfe.RA = rac
	wfe.SA = sac

	wfe.SubscriberAgreementURL = c.WFE.SubscriberAgreementURL
	wfe.AllowOrigins = c.WFE.AllowOrigins
	wfe.AcceptRevocationReason = c.WFE.AcceptRevocationReason
	wfe.AllowAuthzDeactivation = c.WFE.AllowAuthzDeactivation
	wfe.DirectoryCAAIdentity = c.WFE.DirectoryCAAIdentity
	wfe.DirectoryWebsite = c.WFE.DirectoryWebsite

	wfe.IssuerCert, err = cmd.LoadCert(c.Common.IssuerCert)
	cmd.FailOnError(err, fmt.Sprintf("Couldn't read issuer cert [%s]", c.Common.IssuerCert))

	logger.Info(fmt.Sprintf("WFE using key policy: %#v", kp))

	logger.Info(fmt.Sprintf("Server running, listening on %s...\n", c.WFE.ListenAddress))
	handler := wfe.Handler()
	srv := &http.Server{
		Addr:    c.WFE.ListenAddress,
		Handler: handler,
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
			Handler: handler,
		}
		go func() {
			err := tlsSrv.ListenAndServeTLS(c.WFE.ServerCertificatePath, c.WFE.ServerKeyPath)
			if err != nil && err != http.ErrServerClosed {
				cmd.FailOnError(err, "Running TLS server")
			}
		}()
	}

	done := make(chan bool)
	go cmd.CatchSignals(logger, func() {
		ctx, cancel := context.WithTimeout(context.Background(),
			c.WFE.ShutdownStopTimeout.Duration)
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
