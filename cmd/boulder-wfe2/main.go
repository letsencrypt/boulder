package notmain

import (
	"bytes"
	"context"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/goodkey/sagoodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/grpc/noncebalancer"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/nonce"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	"github.com/letsencrypt/boulder/ratelimits"
	bredis "github.com/letsencrypt/boulder/redis"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/letsencrypt/boulder/wfe2"
)

type Config struct {
	WFE struct {
		DebugAddr string `validate:"required,hostname_port"`

		// ListenAddress is the address:port on which to listen for incoming
		// HTTP requests. Defaults to ":80".
		ListenAddress string `validate:"omitempty,hostname_port"`

		// TLSListenAddress is the address:port on which to listen for incoming
		// HTTPS requests. If none is provided the WFE will not listen for HTTPS
		// requests.
		TLSListenAddress string `validate:"omitempty,hostname_port"`

		// Timeout is the per-request overall timeout. This should be slightly
		// lower than the upstream's timeout when making request to the WFE.
		Timeout config.Duration `validate:"-"`

		ServerCertificatePath string `validate:"required_with=TLSListenAddress"`
		ServerKeyPath         string `validate:"required_with=TLSListenAddress"`

		AllowOrigins []string

		ShutdownStopTimeout config.Duration

		SubscriberAgreementURL string

		TLS cmd.TLSConfig

		RAService *cmd.GRPCClientConfig
		SAService *cmd.GRPCClientConfig

		// GetNonceService is a gRPC config which contains a single SRV name
		// used to lookup nonce-service instances used exclusively for nonce
		// creation. In a multi-DC deployment this should refer to local
		// nonce-service instances only.
		GetNonceService *cmd.GRPCClientConfig

		// RedeemNonceServices contains a map of nonce-service prefixes to
		// gRPC configs we want to use to redeem nonces. In a multi-DC deployment
		// this should contain all nonce-services from all DCs as we want to be
		// able to redeem nonces generated at any DC.
		//
		// DEPRECATED: See RedeemNonceService, below.
		// TODO (#6610) Remove this after all configs have migrated to
		// `RedeemNonceService`.
		RedeemNonceServices map[string]cmd.GRPCClientConfig `validate:"required_without=RedeemNonceService,omitempty,min=1,dive"`

		// RedeemNonceService is a gRPC config which contains a list of SRV
		// names used to lookup nonce-service instances used exclusively for
		// nonce redemption. In a multi-DC deployment this should contain both
		// local and remote nonce-service instances.
		RedeemNonceService *cmd.GRPCClientConfig `validate:"required_without=RedeemNonceServices"`

		// NoncePrefixKey is a secret used for deriving the prefix of each nonce
		// instance. It should contain 256 bits of random data to be suitable as
		// an HMAC-SHA256 key (e.g. the output of `openssl rand -hex 32`). In a
		// multi-DC deployment this value should be the same across all
		// boulder-wfe and nonce-service instances.
		NoncePrefixKey cmd.PasswordConfig `validate:"-"`

		// Chains is a list of lists of certificate filenames. Each inner list is
		// a chain (starting with the issuing intermediate, followed by one or
		// more additional certificates, up to and including a root) which we are
		// willing to serve. Chains that start with a given intermediate will only
		// be offered for certificates which were issued by the key pair represented
		// by that intermediate. The first chain representing any given issuing
		// key pair will be the default for that issuer, served if the client does
		// not request a specific chain.
		Chains [][]string `validate:"required,min=1,dive,min=2,dive,required"`

		Features map[string]bool

		// DirectoryCAAIdentity is used for the /directory response's "meta"
		// element's "caaIdentities" field. It should match the VA's "issuerDomain"
		// configuration value (this value is the one used to enforce CAA)
		DirectoryCAAIdentity string `validate:"required,fqdn"`
		// DirectoryWebsite is used for the /directory response's "meta" element's
		// "website" field.
		DirectoryWebsite string `validate:"required,url"`

		// ACMEv2 requests (outside some registration/revocation messages) use a JWS with
		// a KeyID header containing the full account URL. For new accounts this
		// will be a KeyID based on the HTTP request's Host header and the ACMEv2
		// account path. For legacy ACMEv1 accounts we need to whitelist the account
		// ID prefix that legacy accounts would have been using based on the Host
		// header of the WFE1 instance and the legacy 'reg' path component. This
		// will differ in configuration for production and staging.
		LegacyKeyIDPrefix string `validate:"required,url"`

		// GoodKey is an embedded config stanza for the goodkey library.
		GoodKey goodkey.Config

		// StaleTimeout determines how old should data be to be accessed via Boulder-specific GET-able APIs
		StaleTimeout config.Duration `validate:"-"`

		// AuthorizationLifetimeDays defines how long authorizations will be
		// considered valid for. The WFE uses this to find the creation date of
		// authorizations by subtracing this value from the expiry. It should match
		// the value configured in the RA.
		AuthorizationLifetimeDays int `validate:"required,min=1,max=397"`

		// PendingAuthorizationLifetimeDays defines how long authorizations may be in
		// the pending state before expiry. The WFE uses this to find the creation
		// date of pending authorizations by subtracting this value from the expiry.
		// It should match the value configured in the RA.
		PendingAuthorizationLifetimeDays int `validate:"required,min=1,max=29"`

		AccountCache *CacheConfig

		Limiter struct {
			// Redis contains the configuration necessary to connect to Redis
			// for rate limiting. This field is required to enable rate
			// limiting.
			Redis *bredis.Config `validate:"required_with=Defaults"`

			// Defaults is a path to a YAML file containing default rate limits.
			// See: ratelimits/README.md for details. This field is required to
			// enable rate limiting. If any individual rate limit is not set,
			// that limit will be disabled.
			Defaults string `validate:"required_with=Redis"`

			// Overrides is a path to a YAML file containing overrides for the
			// default rate limits. See: ratelimits/README.md for details. If
			// this field is not set, all requesters will be subject to the
			// default rate limits.
			Overrides string
		}
	}

	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig

	// OpenTelemetryHTTPConfig configures tracing on incoming HTTP requests
	OpenTelemetryHTTPConfig cmd.OpenTelemetryHTTPConfig
}

type CacheConfig struct {
	Size int
	TTL  config.Duration
}

// loadChain takes a list of filenames containing pem-formatted certificates,
// and returns a chain representing all of those certificates in order. It
// ensures that the resulting chain is valid. The final file is expected to be
// a root certificate, which the chain will be verified against, but which will
// not be included in the resulting chain.
func loadChain(certFiles []string) (*issuance.Certificate, []byte, error) {
	certs, err := issuance.LoadChain(certFiles)
	if err != nil {
		return nil, nil, err
	}

	// Iterate over all certs appending their pem to the buf.
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write([]byte("\n"))
		buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}

	return certs[0], buf.Bytes(), nil
}

func setupWFE(c Config, scope prometheus.Registerer, clk clock.Clock) (rapb.RegistrationAuthorityClient, sapb.StorageAuthorityReadOnlyClient, nonce.Getter, map[string]nonce.Redeemer, nonce.Redeemer, string) {
	tlsConfig, err := c.WFE.TLS.Load(scope)
	cmd.FailOnError(err, "TLS config")

	raConn, err := bgrpc.ClientSetup(c.WFE.RAService, tlsConfig, scope, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA")
	rac := rapb.NewRegistrationAuthorityClient(raConn)

	saConn, err := bgrpc.ClientSetup(c.WFE.SAService, tlsConfig, scope, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := sapb.NewStorageAuthorityReadOnlyClient(saConn)

	// TODO(#6610) Refactor these checks.
	if c.WFE.RedeemNonceService != nil && c.WFE.RedeemNonceServices != nil {
		cmd.Fail("Only one of 'redeemNonceService' or 'redeemNonceServices' should be configured.")
	}
	if c.WFE.RedeemNonceService == nil && c.WFE.RedeemNonceServices == nil {
		cmd.Fail("One of 'redeemNonceService' or 'redeemNonceServices' must be configured.")
	}
	if c.WFE.RedeemNonceService != nil && c.WFE.NoncePrefixKey.PasswordFile == "" {
		cmd.Fail("'noncePrefixKey' must be configured if 'redeemNonceService' is configured.")
	}
	if c.WFE.GetNonceService == nil {
		cmd.Fail("'getNonceService' must be configured")
	}

	var rncKey string
	if c.WFE.NoncePrefixKey.PasswordFile != "" {
		rncKey, err = c.WFE.NoncePrefixKey.Pass()
		cmd.FailOnError(err, "Failed to load noncePrefixKey")
	}

	getNonceConn, err := bgrpc.ClientSetup(c.WFE.GetNonceService, tlsConfig, scope, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to get nonce service")
	gnc := nonce.NewGetter(getNonceConn)

	var rnc nonce.Redeemer
	var npm map[string]nonce.Redeemer
	if c.WFE.RedeemNonceService != nil {
		// Dispatch nonce redemption RPCs dynamically.
		if c.WFE.RedeemNonceService.SRVResolver != noncebalancer.SRVResolverScheme {
			cmd.Fail(fmt.Sprintf(
				"'redeemNonceService.SRVResolver' must be set to %q", noncebalancer.SRVResolverScheme),
			)
		}
		redeemNonceConn, err := bgrpc.ClientSetup(c.WFE.RedeemNonceService, tlsConfig, scope, clk)
		cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to redeem nonce service")
		rnc = nonce.NewRedeemer(redeemNonceConn)
	} else {
		// Dispatch nonce redpemption RPCs using a static mapping.
		//
		// TODO(#6610) Remove code below and the `npm` mapping.
		npm = make(map[string]nonce.Redeemer)
		for prefix, serviceConfig := range c.WFE.RedeemNonceServices {
			serviceConfig := serviceConfig
			conn, err := bgrpc.ClientSetup(&serviceConfig, tlsConfig, scope, clk)
			cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to redeem nonce service")
			npm[prefix] = nonce.NewRedeemer(conn)
		}
	}

	return rac, sac, gnc, npm, rnc, rncKey
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

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(c.WFE.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	certChains := map[issuance.IssuerNameID][][]byte{}
	issuerCerts := map[issuance.IssuerNameID]*issuance.Certificate{}
	if c.WFE.Chains == nil {
		cmd.Fail("'chains' must be configured")
	}
	for _, files := range c.WFE.Chains {
		issuer, chain, err := loadChain(files)
		cmd.FailOnError(err, "Failed to load chain")

		id := issuer.NameID()
		certChains[id] = append(certChains[id], chain)
		// This may overwrite a previously-set issuerCert (e.g. if there are two
		// chains for the same issuer, but with different versions of the same
		// same intermediate issued by different roots). This is okay, as the
		// only truly important content here is the public key to verify other
		// certs.
		issuerCerts[id] = issuer
	}

	stats, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.WFE.DebugAddr)
	logger.Info(cmd.VersionString())

	clk := cmd.Clock()

	rac, sac, gnc, npm, rnc, npKey := setupWFE(c, stats, clk)

	kp, err := sagoodkey.NewKeyPolicy(&c.WFE.GoodKey, sac.KeyBlocked)
	cmd.FailOnError(err, "Unable to create key policy")

	if c.WFE.StaleTimeout.Duration == 0 {
		c.WFE.StaleTimeout.Duration = time.Minute * 10
	}

	// Baseline Requirements v1.8.1 section 4.2.1: "any reused data, document,
	// or completed validation MUST be obtained no more than 398 days prior
	// to issuing the Certificate". If unconfigured or the configured value is
	// greater than 397 days, bail out.
	if c.WFE.AuthorizationLifetimeDays <= 0 || c.WFE.AuthorizationLifetimeDays > 397 {
		cmd.Fail("authorizationLifetimeDays value must be greater than 0 and less than 398")
	}
	authorizationLifetime := time.Duration(c.WFE.AuthorizationLifetimeDays) * 24 * time.Hour

	// The Baseline Requirements v1.8.1 state that validation tokens "MUST
	// NOT be used for more than 30 days from its creation". If unconfigured
	// or the configured value pendingAuthorizationLifetimeDays is greater
	// than 29 days, bail out.
	if c.WFE.PendingAuthorizationLifetimeDays <= 0 || c.WFE.PendingAuthorizationLifetimeDays > 29 {
		cmd.Fail("pendingAuthorizationLifetimeDays value must be greater than 0 and less than 30")
	}
	pendingAuthorizationLifetime := time.Duration(c.WFE.PendingAuthorizationLifetimeDays) * 24 * time.Hour

	var limiter *ratelimits.Limiter
	var limiterRedis *bredis.Ring
	if c.WFE.Limiter.Defaults != "" {
		// Setup rate limiting.
		limiterRedis, err = bredis.NewRingFromConfig(*c.WFE.Limiter.Redis, stats, logger)
		cmd.FailOnError(err, "Failed to create Redis ring")

		source := ratelimits.NewRedisSource(limiterRedis.Ring, clk, stats)
		limiter, err = ratelimits.NewLimiter(clk, source, c.WFE.Limiter.Defaults, c.WFE.Limiter.Overrides, stats)
		cmd.FailOnError(err, "Failed to create rate limiter")
	}

	var accountGetter wfe2.AccountGetter
	if c.WFE.AccountCache != nil {
		accountGetter = wfe2.NewAccountCache(sac,
			c.WFE.AccountCache.Size,
			c.WFE.AccountCache.TTL.Duration,
			clk,
			stats)
	} else {
		accountGetter = sac
	}
	wfe, err := wfe2.NewWebFrontEndImpl(
		stats,
		clk,
		kp,
		certChains,
		issuerCerts,
		logger,
		c.WFE.Timeout.Duration,
		c.WFE.StaleTimeout.Duration,
		authorizationLifetime,
		pendingAuthorizationLifetime,
		rac,
		sac,
		gnc,
		npm,
		rnc,
		npKey,
		accountGetter,
		limiter,
	)
	cmd.FailOnError(err, "Unable to create WFE")

	wfe.SubscriberAgreementURL = c.WFE.SubscriberAgreementURL
	wfe.AllowOrigins = c.WFE.AllowOrigins
	wfe.DirectoryCAAIdentity = c.WFE.DirectoryCAAIdentity
	wfe.DirectoryWebsite = c.WFE.DirectoryWebsite
	wfe.LegacyKeyIDPrefix = c.WFE.LegacyKeyIDPrefix

	logger.Infof("WFE using key policy: %#v", kp)

	logger.Infof("Server running, listening on %s....", c.WFE.ListenAddress)
	handler := wfe.Handler(stats, c.OpenTelemetryHTTPConfig.Options()...)

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

	// When main is ready to exit (because it has received a shutdown signal),
	// gracefully shutdown the servers. Calling these shutdown functions causes
	// ListenAndServe() and ListenAndServeTLS() to immediately return, then waits
	// for any lingering connection-handling goroutines to finish their work.
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), c.WFE.ShutdownStopTimeout.Duration)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = tlsSrv.Shutdown(ctx)
		limiterRedis.StopLookups()
		oTelShutdown(ctx)
	}()

	cmd.WaitForSignal()
}

func init() {
	cmd.RegisterCommand("boulder-wfe2", main, &cmd.ConfigValidator{Config: &Config{}})
}
