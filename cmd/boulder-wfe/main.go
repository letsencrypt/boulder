package notmain

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/honeycombio/beeline-go"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/grpc"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	noncepb "github.com/letsencrypt/boulder/nonce/proto"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/wfe"
	"github.com/prometheus/client_golang/prometheus"
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

		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig
		// GetNonceService contains a gRPC config for any nonce-service instances
		// which we want to retrieve nonces from. In a multi-DC deployment this
		// should refer to any local nonce-service instances.
		GetNonceService *cmd.GRPCClientConfig
		// RedeemNonceServices contains a map of nonce-service prefixes to
		// gRPC configs we want to use to redeem nonces. In a multi-DC deployment
		// this should contain all nonce-services from all DCs as we want to be
		// able to redeem nonces generated at any DC.
		RedeemNonceServices map[string]cmd.GRPCClientConfig

		Features map[string]bool

		// DirectoryCAAIdentity is used for the /directory response's "meta"
		// element's "caaIdentities" field. It should match the VA's "issuerDomain"
		// configuration value (this value is the one used to enforce CAA)
		DirectoryCAAIdentity string
		// DirectoryWebsite is used for the /directory response's "meta" element's
		// "website" field.
		DirectoryWebsite string

		// BlockedKeyFile is the path to a YAML file containing Base64 encoded
		// SHA256 hashes of SubjectPublicKeyInfo's that should be considered
		// administratively blocked.
		BlockedKeyFile string
	}

	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig

	Common struct {
		IssuerCert string
	}
}

func setupWFE(c config, logger blog.Logger, stats prometheus.Registerer, clk clock.Clock) (rapb.RegistrationAuthorityClient, sapb.StorageAuthorityClient, noncepb.NonceServiceClient, map[string]noncepb.NonceServiceClient) {
	tlsConfig, err := c.WFE.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clientMetrics := bgrpc.NewClientMetrics(stats)
	raConn, err := bgrpc.ClientSetup(c.WFE.RAService, tlsConfig, clientMetrics, clk, grpc.CancelTo408Interceptor)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA")
	rac := rapb.NewRegistrationAuthorityClient(raConn)

	saConn, err := bgrpc.ClientSetup(c.WFE.SAService, tlsConfig, clientMetrics, clk, grpc.CancelTo408Interceptor)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := sapb.NewStorageAuthorityClient(saConn)

	var rns noncepb.NonceServiceClient
	npm := map[string]noncepb.NonceServiceClient{}
	if c.WFE.GetNonceService != nil {
		rnsConn, err := bgrpc.ClientSetup(c.WFE.GetNonceService, tlsConfig, clientMetrics, clk, grpc.CancelTo408Interceptor)
		cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to get nonce service")
		rns = noncepb.NewNonceServiceClient(rnsConn)
		for prefix, serviceConfig := range c.WFE.RedeemNonceServices {
			serviceConfig := serviceConfig
			conn, err := bgrpc.ClientSetup(&serviceConfig, tlsConfig, clientMetrics, clk, grpc.CancelTo408Interceptor)
			cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to redeem nonce service")
			npm[prefix] = noncepb.NewNonceServiceClient(conn)
		}
	}

	return rac, sac, rns, npm
}

type errorWriter struct {
	blog.Logger
}

func (ew errorWriter) Write(p []byte) (n int, err error) {
	// log.Logger will append a newline to all messages before calling
	// Write. Our log checksum checker doesn't like newlines, because
	// syslog will strip them out so the calculated checksums will
	// differ. So that we don't hit this corner case for every line
	// logged from inside net/http.Server we strip the newline before
	// we get to the checksum generator.
	p = bytes.TrimRight(p, "\n")
	ew.Logger.Err(fmt.Sprintf("net/http.Server: %s", string(p)))
	return
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

	bc, err := c.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

	stats, logger := cmd.StatsAndLogging(c.Syslog, c.WFE.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	clk := cmd.Clock()

	rac, sac, rns, npm := setupWFE(c, logger, stats, clk)
	// don't load any weak keys, but do load blocked keys
	kp, err := goodkey.NewKeyPolicy("", c.WFE.BlockedKeyFile, sac.KeyBlocked)
	cmd.FailOnError(err, "Unable to create key policy")
	wfe, err := wfe.NewWebFrontEndImpl(stats, clk, kp, rns, npm, logger)
	cmd.FailOnError(err, "Unable to create WFE")
	wfe.RA = rac
	wfe.SA = sac

	wfe.SubscriberAgreementURL = c.WFE.SubscriberAgreementURL
	wfe.AllowOrigins = c.WFE.AllowOrigins
	wfe.DirectoryCAAIdentity = c.WFE.DirectoryCAAIdentity
	wfe.DirectoryWebsite = c.WFE.DirectoryWebsite

	wfe.IssuerCert, err = issuance.LoadCertificate(c.Common.IssuerCert)
	cmd.FailOnError(err, fmt.Sprintf("Couldn't load issuer cert [%s]", c.Common.IssuerCert))

	logger.Infof("WFE using key policy: %#v", kp)

	logger.Infof("Server running, listening on %s...", c.WFE.ListenAddress)
	handler := wfe.Handler(stats)
	srv := http.Server{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         c.WFE.ListenAddress,
		ErrorLog:     log.New(errorWriter{logger}, "", 0),
		Handler:      handler,
	}

	go func() {
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			cmd.FailOnError(err, "Running HTTP server")
		}
	}()

	tlsSrv := http.Server{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         c.WFE.TLSListenAddress,
		ErrorLog:     log.New(errorWriter{logger}, "", 0),
		Handler:      handler,
	}
	if tlsSrv.Addr != "" {
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
		_ = tlsSrv.Shutdown(ctx)
		done <- true
	})

	// https://godoc.org/net/http#Server.Shutdown:
	// When Shutdown is called, Serve, ListenAndServe, and ListenAndServeTLS
	// immediately return ErrServerClosed. Make sure the program doesn't exit and
	// waits instead for Shutdown to return.
	<-done
}

func init() {
	cmd.RegisterCommand("boulder-wfe", main)
}
