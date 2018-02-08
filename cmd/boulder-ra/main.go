package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/bdns"
	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/ctpolicy"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/policy"
	pubPB "github.com/letsencrypt/boulder/publisher/proto"
	"github.com/letsencrypt/boulder/ra"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	vaPB "github.com/letsencrypt/boulder/va/proto"
)

type config struct {
	RA struct {
		cmd.ServiceConfig
		cmd.HostnamePolicyConfig

		RateLimitPoliciesFilename string

		MaxContactsPerRegistration int

		// UseIsSafeDomain determines whether to call VA.IsSafeDomain
		UseIsSafeDomain bool // TODO: remove after va IsSafeDomain deploy

		// The number of times to try a DNS query (that has a temporary error)
		// before giving up. May be short-circuited by deadlines. A zero value
		// will be turned into 1.
		DNSTries int

		SAService        *cmd.GRPCClientConfig
		VAService        *cmd.GRPCClientConfig
		CAService        *cmd.GRPCClientConfig
		PublisherService *cmd.GRPCClientConfig

		MaxNames     int
		DoNotForceCN bool

		// Controls behaviour of the RA when asked to create a new authz for
		// a name/regID that already has a valid authz. False preserves historic
		// behaviour and ignores the existing authz and creates a new one. True
		// instructs the RA to reuse the previously created authz in lieu of
		// creating another.
		ReuseValidAuthz bool

		// AuthorizationLifetimeDays defines how long authorizations will be
		// considered valid for. Given a value of 300 days when used with a 90-day
		// cert lifetime, this allows creation of certs that will cover a whole
		// year, plus a grace period of a month.
		AuthorizationLifetimeDays int

		// PendingAuthorizationLifetimeDays defines how long authorizations may be in
		// the pending state. If you can't respond to a challenge this quickly, then
		// you need to request a new challenge.
		PendingAuthorizationLifetimeDays int

		// WeakKeyFile is the path to a JSON file containing truncated RSA modulus
		// hashes of known easily enumerable keys.
		WeakKeyFile string

		OrderLifetime cmd.ConfigDuration

		// CTLogGroups contains groupings of CT logs which we want SCTs from.
		// When we retrieve SCTs we will submit the certificate to each log
		// in a group and the first SCT returned will be used. This allows
		// us to comply with Chrome CT policy which requires one SCT from a
		// Google log and one SCT from any other log included in their policy.
		CTLogGroups [][]cmd.LogDescription

		Features map[string]bool
	}

	PA cmd.PAConfig

	Syslog cmd.SyslogConfig

	Common struct {
		DNSResolver               string
		DNSTimeout                string
		DNSAllowLoopbackAddresses bool
	}
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

	err = features.Set(c.RA.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.RA.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	// Validate PA config and set defaults if needed
	cmd.FailOnError(c.PA.CheckChallenges(), "Invalid PA configuration")

	pa, err := policy.New(c.PA.Challenges)
	cmd.FailOnError(err, "Couldn't create PA")

	if c.RA.HostnamePolicyFile == "" {
		cmd.FailOnError(fmt.Errorf("HostnamePolicyFile must be provided."), "")
	}
	err = pa.SetHostnamePolicyFile(c.RA.HostnamePolicyFile)
	cmd.FailOnError(err, "Couldn't load hostname policy file")

	if c.PA.ChallengesWhitelistFile != "" {
		err = pa.SetChallengesWhitelistFile(c.PA.ChallengesWhitelistFile)
		cmd.FailOnError(err, "Couldn't load challenges whitelist file")
	} else {
		logger.Info("No challengesWhitelistFile given, not loading")
	}

	var tls *tls.Config
	if c.RA.TLS.CertFile != nil {
		tls, err = c.RA.TLS.Load()
		cmd.FailOnError(err, "TLS config")
	}

	clientMetrics := bgrpc.NewClientMetrics(scope)
	vaConn, err := bgrpc.ClientSetup(c.RA.VAService, tls, clientMetrics)
	cmd.FailOnError(err, "Unable to create VA client")
	vac := bgrpc.NewValidationAuthorityGRPCClient(vaConn)

	caaClient := vaPB.NewCAAClient(vaConn)

	caConn, err := bgrpc.ClientSetup(c.RA.CAService, tls, clientMetrics)
	cmd.FailOnError(err, "Unable to create CA client")
	// Build a CA client that is only capable of issuing certificates, not
	// signing OCSP. TODO(jsha): Once we've fully moved to gRPC, replace this
	// with a plain caPB.NewCertificateAuthorityClient.
	cac := bgrpc.NewCertificateAuthorityClient(caPB.NewCertificateAuthorityClient(caConn), nil)

	var pubc core.Publisher
	var ctp *ctpolicy.CTPolicy
	if c.RA.PublisherService != nil {
		conn, err := bgrpc.ClientSetup(c.RA.PublisherService, tls, clientMetrics)
		cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to Publisher")
		pubc = bgrpc.NewPublisherClientWrapper(pubPB.NewPublisherClient(conn))

		if c.RA.CTLogGroups != nil {
			ctp = ctpolicy.New(pubc, c.RA.CTLogGroups, logger)
		}
	}

	conn, err := bgrpc.ClientSetup(c.RA.SAService, tls, clientMetrics)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(conn))

	// TODO(patf): remove once RA.authorizationLifetimeDays is deployed
	authorizationLifetime := 300 * 24 * time.Hour
	if c.RA.AuthorizationLifetimeDays != 0 {
		authorizationLifetime = time.Duration(c.RA.AuthorizationLifetimeDays) * 24 * time.Hour
	}

	// TODO(patf): remove once RA.pendingAuthorizationLifetimeDays is deployed
	pendingAuthorizationLifetime := 7 * 24 * time.Hour
	if c.RA.PendingAuthorizationLifetimeDays != 0 {
		pendingAuthorizationLifetime = time.Duration(c.RA.PendingAuthorizationLifetimeDays) * 24 * time.Hour
	}

	kp, err := goodkey.NewKeyPolicy(c.RA.WeakKeyFile)
	cmd.FailOnError(err, "Unable to create key policy")

	rai := ra.NewRegistrationAuthorityImpl(
		cmd.Clock(),
		logger,
		scope,
		c.RA.MaxContactsPerRegistration,
		kp,
		c.RA.MaxNames,
		c.RA.DoNotForceCN,
		c.RA.ReuseValidAuthz,
		authorizationLifetime,
		pendingAuthorizationLifetime,
		pubc,
		caaClient,
		c.RA.OrderLifetime.Duration,
		ctp,
	)

	policyErr := rai.SetRateLimitPoliciesFile(c.RA.RateLimitPoliciesFilename)
	cmd.FailOnError(policyErr, "Couldn't load rate limit policies file")
	rai.PA = pa

	raDNSTimeout, err := time.ParseDuration(c.Common.DNSTimeout)
	cmd.FailOnError(err, "Couldn't parse RA DNS timeout")
	dnsTries := c.RA.DNSTries
	if dnsTries < 1 {
		dnsTries = 1
	}
	if !c.Common.DNSAllowLoopbackAddresses {
		rai.DNSClient = bdns.NewDNSClientImpl(
			raDNSTimeout,
			[]string{c.Common.DNSResolver},
			scope,
			cmd.Clock(),
			dnsTries)
	} else {
		rai.DNSClient = bdns.NewTestDNSClientImpl(
			raDNSTimeout,
			[]string{c.Common.DNSResolver},
			scope,
			cmd.Clock(),
			dnsTries)
	}

	rai.VA = vac
	rai.CA = cac
	rai.SA = sac

	err = rai.UpdateIssuedCountForever()
	cmd.FailOnError(err, "Updating total issuance count")

	var grpcSrv *grpc.Server
	if c.RA.GRPC != nil {
		serverMetrics := bgrpc.NewServerMetrics(scope)
		var listener net.Listener
		grpcSrv, listener, err = bgrpc.NewServer(c.RA.GRPC, tls, serverMetrics)
		cmd.FailOnError(err, "Unable to setup RA gRPC server")
		gw := bgrpc.NewRegistrationAuthorityServer(rai)
		rapb.RegisterRegistrationAuthorityServer(grpcSrv, gw)
		go func() {
			err = cmd.FilterShutdownErrors(grpcSrv.Serve(listener))
			cmd.FailOnError(err, "RA gRPC service failed")
		}()
	}

	go cmd.CatchSignals(logger, func() {
		if grpcSrv != nil {
			grpcSrv.GracefulStop()
		}
	})

	select {}
}
