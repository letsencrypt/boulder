package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
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

		ShutdownStopTimeout cmd.ConfigDuration

		SubscriberAgreementURL string

		AcceptRevocationReason bool
		AllowAuthzDeactivation bool

		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig

		Features map[string]bool

		// CertificateChains maps AIA issuer URLs to certificate filenames
		CertificateChains map[string][]string
	}

	SubscriberAgreementURL string

	Syslog cmd.SyslogConfig

	Common struct {
		BaseURL    string
		IssuerCert string
	}
}

// loadChainFile loads a PEM certificate from the chainFile provided. It
// validates that the PEM is well-formed with no leftover bytes, and contains
// only a well-formed X509 certificate. If the chain file meets these
// requirements the PEM bytes from the file are returned, otherwise an error is
// returned.
func loadChainFile(aiaIssuerURL, chainFile string) ([]byte, error) {
	pemBytes, err := ioutil.ReadFile(chainFile)
	if err != nil {
		return nil, fmt.Errorf(
			"CertificateChain entry for AIA issuer url %q has an "+
				"invalid chain file: %q - error reading contents: %s",
			aiaIssuerURL, chainFile, err)
	}
	// Try to decode the contents as PEM
	certBlock, rest := pem.Decode(pemBytes)
	if certBlock == nil {
		return nil, fmt.Errorf(
			"CertificateChain entry for AIA issuer url %q has an "+
				"invalid chain file: %q - contents did not decode as PEM",
			aiaIssuerURL, chainFile)
	}
	// The PEM contents must be a CERTIFICATE
	if certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf(
			"CertificateChain entry for AIA issuer url %q has an "+
				"invalid chain file: %q - PEM block type incorrect, found "+
				"%q, expected \"CERTIFICATE\"",
			aiaIssuerURL, chainFile, certBlock.Type)
	}
	// The PEM Certificate must successfully parse
	if _, err := x509.ParseCertificate(certBlock.Bytes); err != nil {
		return nil, fmt.Errorf(
			"CertificateChain entry for AIA issuer url %q has an "+
				"invalid chain file: %q - certificate bytes failed to parse: %s",
			aiaIssuerURL, chainFile, err)
	}
	// If there are bytes leftover we must reject the file otherwise these
	// leftover bytes will end up in a served certificate chain.
	if len(rest) != 0 {
		return nil, fmt.Errorf(
			"CertificateChain entry for AIA issuer url %q has an "+
				"invalid chain file: %q - PEM contents had unused remainder "+
				"input (%d bytes)",
			aiaIssuerURL, chainFile, len(rest))
	}

	return pemBytes, nil
}

// loadCertificateChains processes the provided chainConfig of AIA Issuer URLs
// and cert filenames. For each AIA issuer URL all of its cert filenames are
// read, validated as PEM certificates, and concatenated together separated by
// newlines. The combined PEM certificate chain contents for each are returned
// in the results map, keyed by the AIA Issuer URL.
func loadCertificateChains(chainConfig map[string][]string) (map[string]string, error) {
	results := make(map[string]string, len(chainConfig))

	// For each AIA Issuer URL we need to read the chain files
	for aiaIssuerURL, chainFiles := range chainConfig {
		var buffer bytes.Buffer

		// There must be at least one chain file specified
		if len(chainFiles) == 0 {
			return nil, fmt.Errorf(
				"CertificateChain entry for AIA issuer url %q has no chain "+
					"file names configured",
				aiaIssuerURL)
		}

		// Read each chain file - it is expected to be a PEM certificate
		for _, c := range chainFiles {
			// Read and validate the chain file contents
			pemBytes, err := loadChainFile(aiaIssuerURL, c)
			if err != nil {
				return nil, err
			}

			// Write the PEM bytes to the result buffer for this AIAIssuer
			buffer.Write(pemBytes)

			// We want each certificate in the chain separated by a \n, with
			// a trailing \n at the end of the file that will serve to space out the
			// end entity certificate that is appended by the WFE2's certificate
			// endpoint.
			buffer.Write([]byte("\n"))
		}

		// Save the full PEM chain contents
		results[aiaIssuerURL] = buffer.String()
	}
	return results, nil
}

func setupWFE(c config, logger blog.Logger, stats metrics.Scope) (core.RegistrationAuthority, core.StorageAuthority) {
	var tls *tls.Config
	var err error
	if c.WFE.TLS.CertFile != nil {
		tls, err = c.WFE.TLS.Load()
		cmd.FailOnError(err, "TLS config")
	}
	clientMetrics := bgrpc.NewClientMetrics(stats)
	raConn, err := bgrpc.ClientSetup(c.WFE.RAService, tls, clientMetrics)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA")
	rac := bgrpc.NewRegistrationAuthorityClient(rapb.NewRegistrationAuthorityClient(raConn))

	saConn, err := bgrpc.ClientSetup(c.WFE.SAService, tls, clientMetrics)
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

	wfe.IssuerCert, err = cmd.LoadCert(c.Common.IssuerCert)
	cmd.FailOnError(err, fmt.Sprintf("Couldn't read issuer cert [%s]", c.Common.IssuerCert))

	wfe.CertificateChains, err = loadCertificateChains(c.WFE.CertificateChains)
	cmd.FailOnError(err, "Couldn't read configured CertificateChains")

	logger.Info(fmt.Sprintf("WFE using key policy: %#v", kp))

	// Set up paths
	wfe.BaseURL = c.Common.BaseURL

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
