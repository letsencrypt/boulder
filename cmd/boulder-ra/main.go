package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"time"

	akamaipb "github.com/letsencrypt/boulder/akamai/proto"
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

		SAService           *cmd.GRPCClientConfig
		VAService           *cmd.GRPCClientConfig
		CAService           *cmd.GRPCClientConfig
		PublisherService    *cmd.GRPCClientConfig
		AkamaiPurgerService *cmd.GRPCClientConfig

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
		CTLogGroups2 []cmd.CTGroup
		// InformationalCTLogs are a set of CT logs we will always submit to
		// but won't ever use the SCTs from. This may be because we want to
		// test them or because they are not yet approved by a browser/root
		// program but we still want our certs to end up there.
		InformationalCTLogs []cmd.LogDescription

		// IssuerCertPath is the path to the intermediate used to issue certificates.
		// It is required if the RevokeAtRA feature is enabled and is used to
		// generate OCSP URLs to purge at revocation time.
		IssuerCertPath string

		Features map[string]bool
	}

	PA cmd.PAConfig

	Syslog cmd.SyslogConfig
}

func main() {
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
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

	if *grpcAddr != "" {
		c.RA.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.RA.DebugAddr = *debugAddr
	}

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.RA.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	// Validate PA config and set defaults if needed
	cmd.FailOnError(c.PA.CheckChallenges(), "Invalid PA configuration")

	pa, err := policy.New(c.PA.Challenges)
	cmd.FailOnError(err, "Couldn't create PA")

	if c.RA.HostnamePolicyFile == "" {
		cmd.Fail("HostnamePolicyFile must be provided.")
	}
	err = pa.SetHostnamePolicyFile(c.RA.HostnamePolicyFile)
	cmd.FailOnError(err, "Couldn't load hostname policy file")

	if features.Enabled(features.RevokeAtRA) && (c.RA.AkamaiPurgerService == nil || c.RA.IssuerCertPath == "") {
		cmd.Fail("If the RevokeAtRA feature is enabled the AkamaiPurgerService and IssuerCertPath config fields must be populated")
	}

	tlsConfig, err := c.RA.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clk := cmd.Clock()

	clientMetrics := bgrpc.NewClientMetrics(scope)
	vaConn, err := bgrpc.ClientSetup(c.RA.VAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Unable to create VA client")
	vac := bgrpc.NewValidationAuthorityGRPCClient(vaConn)

	caaClient := vaPB.NewCAAClient(vaConn)

	caConn, err := bgrpc.ClientSetup(c.RA.CAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Unable to create CA client")
	cac := bgrpc.NewCertificateAuthorityClient(caPB.NewCertificateAuthorityClient(caConn), nil)

	var ctp *ctpolicy.CTPolicy
	conn, err := bgrpc.ClientSetup(c.RA.PublisherService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to Publisher")
	pubc := bgrpc.NewPublisherClientWrapper(pubPB.NewPublisherClient(conn))

	var apc akamaipb.AkamaiPurgerClient
	var issuerCert *x509.Certificate
	if features.Enabled(features.RevokeAtRA) {
		apConn, err := bgrpc.ClientSetup(c.RA.AkamaiPurgerService, tlsConfig, clientMetrics, clk)
		cmd.FailOnError(err, "Unable to create a Akamai Purger client")
		apc = akamaipb.NewAkamaiPurgerClient(apConn)

		issuerCert, err = core.LoadCert(c.RA.IssuerCertPath)
		cmd.FailOnError(err, "Failed to load issuer certificate")
	}

	// Boulder's components assume that there will always be CT logs configured.
	// Issuing a certificate without SCTs embedded is a miss-issuance event in the
	// enviromnent Boulder is built for. Exit early if there is no CTLogGroups2
	// configured.
	if len(c.RA.CTLogGroups2) == 0 {
		cmd.Fail("CTLogGroups2 must not be empty")
	}

	for i, g := range c.RA.CTLogGroups2 {
		// Exit early if any of the log groups specify no logs
		if len(g.Logs) == 0 {
			cmd.Fail(
				fmt.Sprintf("CTLogGroups2 index %d specifies no logs", i))
		}
		for _, l := range g.Logs {
			if l.TemporalSet != nil {
				err := l.Setup()
				cmd.FailOnError(err, "Failed to setup a temporal log set")
			}
		}
	}
	ctp = ctpolicy.New(pubc, c.RA.CTLogGroups2, c.RA.InformationalCTLogs, logger, scope)

	saConn, err := bgrpc.ClientSetup(c.RA.SAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(saConn))

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

	if c.RA.MaxNames == 0 {
		cmd.Fail(fmt.Sprintf("Error in RA config: MaxNames must not be 0"))
	}

	rai := ra.NewRegistrationAuthorityImpl(
		clk,
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
		apc,
		issuerCert,
	)

	policyErr := rai.SetRateLimitPoliciesFile(c.RA.RateLimitPoliciesFilename)
	cmd.FailOnError(policyErr, "Couldn't load rate limit policies file")
	rai.PA = pa

	rai.VA = vac
	rai.CA = cac
	rai.SA = sac

	serverMetrics := bgrpc.NewServerMetrics(scope)
	grpcSrv, listener, err := bgrpc.NewServer(c.RA.GRPC, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup RA gRPC server")
	gw := bgrpc.NewRegistrationAuthorityServer(rai)
	rapb.RegisterRegistrationAuthorityServer(grpcSrv, gw)

	go cmd.CatchSignals(logger, grpcSrv.GracefulStop)

	err = cmd.FilterShutdownErrors(grpcSrv.Serve(listener))
	cmd.FailOnError(err, "RA gRPC service failed")
}
