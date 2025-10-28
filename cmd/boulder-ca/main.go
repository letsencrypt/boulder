package notmain

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/ca"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/ctpolicy/loglist"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/goodkey/sagoodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/policy"
	rapb "github.com/letsencrypt/boulder/ra/proto"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type Config struct {
	CA struct {
		cmd.ServiceConfig

		cmd.HostnamePolicyConfig

		GRPCCA *cmd.GRPCServerConfig

		SAService *cmd.GRPCClientConfig

		SCTService *cmd.GRPCClientConfig

		// Issuance contains all information necessary to load and initialize issuers.
		Issuance struct {
			// The name of the certificate profile to use if one wasn't provided
			// by the RA during NewOrder and Finalize requests. Must match a
			// configured certificate profile or boulder-ca will fail to start.
			//
			// Deprecated: set the defaultProfileName in the RA config instead.
			DefaultCertificateProfileName string `validate:"omitempty,alphanum,min=1,max=32"`

			// One of the profile names must match the value of ra.defaultProfileName
			// or large amounts of issuance will fail.
			CertProfiles map[string]issuance.ProfileConfig `validate:"required,dive,keys,alphanum,min=1,max=32,endkeys"`

			// TODO(#7159): Make this required once all live configs are using it.
			CRLProfile issuance.CRLProfileConfig `validate:"-"`
			Issuers    []issuance.IssuerConfig   `validate:"min=1,dive"`
		}

		// What digits we should prepend to serials after randomly generating them.
		// Deprecated: Use SerialPrefixHex instead.
		SerialPrefix int `validate:"required_without=SerialPrefixHex,omitempty,min=1,max=127"`

		// SerialPrefixHex is the hex string to prepend to serials after randomly
		// generating them. The minimum value is "01" to ensure that at least
		// one bit in the prefix byte is set. The maximum value is "7f" to
		// ensure that the first bit in the prefix byte is not set. The validate
		// library cannot enforce mix/max values on strings, so that is done in
		// NewCertificateAuthorityImpl.
		//
		// TODO(#7213): Replace `required_without` with `required` when SerialPrefix is removed.
		SerialPrefixHex string `validate:"required_without=SerialPrefix,omitempty,hexadecimal,len=2"`

		// MaxNames is the maximum number of subjectAltNames in a single cert.
		// The value supplied MUST be greater than 0 and no more than 100. These
		// limits are per section 7.1 of our combined CP/CPS, under "DV-SSL
		// Subscriber Certificate". The value must match the RA and WFE
		// configurations.
		MaxNames int `validate:"required,min=1,max=100"`

		// GoodKey is an embedded config stanza for the goodkey library.
		GoodKey goodkey.Config

		// Maximum length (in bytes) of a line documenting the signing of a CRL.
		// The name is a carryover from when this config was shared between both
		// OCSP and CRL audit log emission. Recommended to be around 4000.
		OCSPLogMaxLength int

		// CTLogListFile is the path to a JSON file on disk containing the set of
		// all logs trusted by Chrome. The file must match the v3 log list schema:
		// https://www.gstatic.com/ct/log_list/v3/log_list_schema.json
		CTLogListFile string

		// DisableCertService causes the CertificateAuthority gRPC service to not
		// start, preventing any certificates or precertificates from being issued.
		DisableCertService bool

		// DisableCRLService causes the CRLGenerator gRPC service to not start,
		// preventing any CRLs from being issued.
		DisableCRLService bool

		Features features.Config
	}

	PA cmd.PAConfig

	Syslog        cmd.SyslogConfig
	OpenTelemetry cmd.OpenTelemetryConfig
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

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	features.Set(c.CA.Features)

	if *grpcAddr != "" {
		c.CA.GRPCCA.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.CA.DebugAddr = *debugAddr
	}

	serialPrefix := byte(c.CA.SerialPrefix)
	if c.CA.SerialPrefixHex != "" {
		parsedSerialPrefix, err := strconv.ParseUint(c.CA.SerialPrefixHex, 16, 8)
		cmd.FailOnError(err, "Couldn't convert SerialPrefixHex to int")
		serialPrefix = byte(parsedSerialPrefix)
	}

	if c.CA.MaxNames == 0 {
		cmd.Fail("Error in CA config: MaxNames must not be 0")
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.Syslog, c.OpenTelemetry, c.CA.DebugAddr)
	defer oTelShutdown(context.Background())
	logger.Info(cmd.VersionString())

	metrics := ca.NewCAMetrics(scope)

	cmd.FailOnError(c.PA.CheckChallenges(), "Invalid PA configuration")
	cmd.FailOnError(c.PA.CheckIdentifiers(), "Invalid PA configuration")

	pa, err := policy.New(c.PA.Identifiers, c.PA.Challenges, logger)
	cmd.FailOnError(err, "Couldn't create PA")

	if c.CA.HostnamePolicyFile == "" {
		cmd.Fail("HostnamePolicyFile was empty")
	}
	err = pa.LoadIdentPolicyFile(c.CA.HostnamePolicyFile)
	cmd.FailOnError(err, "Couldn't load identifier policy file")

	// Do this before creating the issuers to ensure the log list is loaded before
	// the linters are initialized.
	if c.CA.CTLogListFile != "" {
		err = loglist.InitLintList(c.CA.CTLogListFile)
		cmd.FailOnError(err, "Failed to load CT Log List")
	}

	profiles := make(map[string]*issuance.Profile)
	for name, profileConfig := range c.CA.Issuance.CertProfiles {
		profile, err := issuance.NewProfile(profileConfig)
		cmd.FailOnError(err, "Loading profile")
		profiles[name] = profile
	}

	clk := clock.New()
	var crlShards int
	issuers := make([]*issuance.Issuer, 0, len(c.CA.Issuance.Issuers))
	for i, issuerConfig := range c.CA.Issuance.Issuers {
		// Double check that all issuers have the same number of CRL shards, because
		// crl-updater relies upon that invariant.
		if issuerConfig.CRLShards != 0 && crlShards == 0 {
			crlShards = issuerConfig.CRLShards
		}
		if issuerConfig.CRLShards != crlShards {
			cmd.Fail(fmt.Sprintf("issuer %d has %d shards, want %d", i, issuerConfig.CRLShards, crlShards))
		}
		// Also check that all the profiles they list actually exist.
		for _, profile := range issuerConfig.Profiles {
			_, found := profiles[profile]
			if !found {
				cmd.Fail(fmt.Sprintf("issuer %d lists unrecognized profile %q", i, profile))
			}
		}

		issuer, err := issuance.LoadIssuer(issuerConfig, clk)
		cmd.FailOnError(err, "Loading issuer")
		issuers = append(issuers, issuer)
	}

	if len(c.CA.Issuance.CertProfiles) == 0 {
		cmd.Fail("At least one profile must be configured")
	}

	tlsConfig, err := c.CA.TLS.Load(scope)
	cmd.FailOnError(err, "TLS config")

	saConn, err := bgrpc.ClientSetup(c.CA.SAService, tlsConfig, scope, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sa := sapb.NewStorageAuthorityClient(saConn)

	var sctService rapb.SCTProviderClient
	if c.CA.SCTService != nil {
		sctConn, err := bgrpc.ClientSetup(c.CA.SCTService, tlsConfig, scope, clk)
		cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to RA for SCTs")
		sctService = rapb.NewSCTProviderClient(sctConn)
	}

	kp, err := sagoodkey.NewPolicy(&c.CA.GoodKey, sa.KeyBlocked)
	cmd.FailOnError(err, "Unable to create key policy")

	srv := bgrpc.NewServer(c.CA.GRPCCA, logger)

	if !c.CA.DisableCRLService {
		crli, err := ca.NewCRLImpl(
			issuers,
			c.CA.Issuance.CRLProfile,
			c.CA.OCSPLogMaxLength,
			logger,
			metrics,
		)
		cmd.FailOnError(err, "Failed to create CRL impl")

		srv = srv.Add(&capb.CRLGenerator_ServiceDesc, crli)
	}

	if !c.CA.DisableCertService {
		cai, err := ca.NewCertificateAuthorityImpl(
			sa,
			sctService,
			pa,
			issuers,
			profiles,
			serialPrefix,
			c.CA.MaxNames,
			kp,
			logger,
			metrics,
			clk)
		cmd.FailOnError(err, "Failed to create CA impl")

		srv = srv.Add(&capb.CertificateAuthority_ServiceDesc, cai)
	}

	start, err := srv.Build(tlsConfig, scope, clk)
	cmd.FailOnError(err, "Unable to setup CA gRPC server")

	cmd.FailOnError(start(), "CA gRPC service failed")
}

func init() {
	cmd.RegisterCommand("boulder-ca", main, &cmd.ConfigValidator{Config: &Config{}})
}
