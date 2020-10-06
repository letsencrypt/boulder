package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/beeker1121/goque"
	cfsslConfig "github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	pkcs11key "github.com/letsencrypt/pkcs11key/v4"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/letsencrypt/boulder/ca"
	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/lint"
	"github.com/letsencrypt/boulder/policy"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type config struct {
	CA struct {
		cmd.ServiceConfig
		cmd.DBConfig
		cmd.HostnamePolicyConfig

		GRPCCA            *cmd.GRPCServerConfig
		GRPCOCSPGenerator *cmd.GRPCServerConfig

		SAService *cmd.GRPCClientConfig

		// CFSSL contains CFSSL-specific configs as specified by that library.
		CFSSL cfsslConfig.Config
		// RSAProfile and ECDSAProfile name which of the profiles specified in the
		// CFSSL config should be used when issuing RSA and ECDSA certs, respectively.
		RSAProfile   string
		ECDSAProfile string
		// Issuers contains configuration information for each issuer cert and key
		// this CA knows about. The first in the list is used as the default.
		// Only used by CFSSL.
		Issuers []IssuerConfig

		// Issuance contains all information necessary to load and initialize non-CFSSL issuers.
		Issuance struct {
			Profile      issuance.ProfileConfig
			Issuers      []issuance.IssuerConfig
			IgnoredLints []string
		}

		// How long issued certificates are valid for, should match expiry field
		// in cfssl config.
		Expiry cmd.ConfigDuration

		// How far back certificates should be backdated, should match backdate
		// field in cfssl config.
		Backdate cmd.ConfigDuration

		// What digits we should prepend to serials after randomly generating them.
		SerialPrefix int

		// The maximum number of subjectAltNames in a single certificate
		MaxNames int

		// LifespanOCSP is how long OCSP responses are valid for; It should be longer
		// than the minTimeToExpiry field for the OCSP Updater.
		LifespanOCSP cmd.ConfigDuration

		// WeakKeyFile is the path to a JSON file containing truncated RSA modulus
		// hashes of known easily enumerable keys.
		WeakKeyFile string

		// BlockedKeyFile is the path to a YAML file containing Base64 encoded
		// SHA256 hashes of SubjectPublicKeyInfo's that should be considered
		// administratively blocked.
		BlockedKeyFile string

		// Path to directory holding orphan queue files, if not provided an orphan queue
		// is not used.
		OrphanQueueDir string

		Features map[string]bool
	}

	PA cmd.PAConfig

	Syslog cmd.SyslogConfig
}

// IssuerConfig contains info about an issuer: private key and issuer cert.
// It should contain either a File path to a PEM-format private key,
// or a PKCS11Config defining how to load a module for an HSM. Used by CFSSL.
type IssuerConfig struct {
	// A file from which a pkcs11key.Config will be read and parsed, if present
	ConfigFile string
	File       string
	PKCS11     *pkcs11key.Config
	CertFile   string
	// Number of sessions to open with the HSM. For maximum performance,
	// this should be equal to the number of cores in the HSM. Defaults to 1.
	NumSessions int
}

func loadCFSSLIssuers(configs []IssuerConfig) ([]ca.Issuer, error) {
	var issuers []ca.Issuer
	for _, issuerConfig := range configs {
		signer, cert, err := loadCFSSLIssuer(issuerConfig)
		cmd.FailOnError(err, "Couldn't load private key")
		issuers = append(issuers, ca.Issuer{
			Signer: signer,
			Cert:   cert,
		})
	}
	return issuers, nil
}

func loadCFSSLIssuer(issuerConfig IssuerConfig) (crypto.Signer, *issuance.Certificate, error) {
	cert, err := issuance.LoadCertificate(issuerConfig.CertFile)
	if err != nil {
		return nil, nil, err
	}

	signer, err := loadCFSSLSigner(issuerConfig, cert.Certificate)
	if err != nil {
		return nil, nil, err
	}

	if !core.KeyDigestEquals(signer.Public(), cert.PublicKey) {
		return nil, nil, fmt.Errorf("Issuer key did not match issuer cert %s", issuerConfig.CertFile)
	}
	return signer, cert, err
}

func loadCFSSLSigner(issuerConfig IssuerConfig, cert *x509.Certificate) (crypto.Signer, error) {
	if issuerConfig.File != "" {
		keyBytes, err := ioutil.ReadFile(issuerConfig.File)
		if err != nil {
			return nil, fmt.Errorf("Could not read key file %s", issuerConfig.File)
		}

		signer, err := helpers.ParsePrivateKeyPEM(keyBytes)
		if err != nil {
			return nil, err
		}
		return signer, nil
	}

	var pkcs11Config *pkcs11key.Config
	if issuerConfig.ConfigFile != "" {
		contents, err := ioutil.ReadFile(issuerConfig.ConfigFile)
		if err != nil {
			return nil, err
		}
		pkcs11Config = new(pkcs11key.Config)
		err = json.Unmarshal(contents, pkcs11Config)
		if err != nil {
			return nil, err
		}
	} else {
		pkcs11Config = issuerConfig.PKCS11
	}
	if pkcs11Config.Module == "" ||
		pkcs11Config.TokenLabel == "" ||
		pkcs11Config.PIN == "" {
		return nil, fmt.Errorf("Missing a field in pkcs11Config %#v", pkcs11Config)
	}
	numSessions := issuerConfig.NumSessions
	if numSessions <= 0 {
		numSessions = 1
	}
	return pkcs11key.NewPool(numSessions, pkcs11Config.Module,
		pkcs11Config.TokenLabel, pkcs11Config.PIN, cert.PublicKey)
}

func loadBoulderIssuers(profileConfig issuance.ProfileConfig, issuerConfigs []issuance.IssuerConfig, ignoredLints []string) ([]*issuance.Issuer, error) {
	issuers := make([]*issuance.Issuer, 0, len(issuerConfigs))
	for _, issuerConfig := range issuerConfigs {
		profile, err := issuance.NewProfile(profileConfig, issuerConfig)
		if err != nil {
			return nil, err
		}

		cert, signer, err := issuance.LoadIssuer(issuerConfig.Location)
		if err != nil {
			return nil, err
		}

		linter, err := lint.NewLinter(signer, ignoredLints)
		if err != nil {
			return nil, err
		}

		issuer, err := issuance.NewIssuer(cert, signer, profile, linter, cmd.Clock())
		if err != nil {
			return nil, err
		}

		issuers = append(issuers, issuer)
	}
	return issuers, nil
}

func main() {
	caAddr := flag.String("ca-addr", "", "CA gRPC listen address override")
	ocspAddr := flag.String("ocsp-addr", "", "OCSP gRPC listen address override")
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

	err = features.Set(c.CA.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	if *caAddr != "" {
		c.CA.GRPCCA.Address = *caAddr
	}
	if *ocspAddr != "" {
		c.CA.GRPCOCSPGenerator.Address = *ocspAddr
	}
	if *debugAddr != "" {
		c.CA.DebugAddr = *debugAddr
	}

	if c.CA.MaxNames == 0 {
		cmd.Fail("Error in CA config: MaxNames must not be 0")
	}

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.CA.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	cmd.FailOnError(c.PA.CheckChallenges(), "Invalid PA configuration")

	pa, err := policy.New(c.PA.Challenges)
	cmd.FailOnError(err, "Couldn't create PA")

	if c.CA.HostnamePolicyFile == "" {
		cmd.FailOnError(fmt.Errorf("HostnamePolicyFile was empty."), "")
	}
	err = pa.SetHostnamePolicyFile(c.CA.HostnamePolicyFile)
	cmd.FailOnError(err, "Couldn't load hostname policy file")

	var cfsslIssuers []ca.Issuer
	var boulderIssuers []*issuance.Issuer
	if features.Enabled(features.NonCFSSLSigner) {
		boulderIssuers, err = loadBoulderIssuers(c.CA.Issuance.Profile, c.CA.Issuance.Issuers, c.CA.Issuance.IgnoredLints)
		cmd.FailOnError(err, "Couldn't load issuers")
	} else {
		cfsslIssuers, err = loadCFSSLIssuers(c.CA.Issuers)
		cmd.FailOnError(err, "Couldn't load issuers")
	}

	tlsConfig, err := c.CA.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clk := cmd.Clock()

	clientMetrics := bgrpc.NewClientMetrics(scope)
	conn, err := bgrpc.ClientSetup(c.CA.SAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sa := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(conn))

	kp, err := goodkey.NewKeyPolicy(c.CA.WeakKeyFile, c.CA.BlockedKeyFile, sa.KeyBlocked)
	cmd.FailOnError(err, "Unable to create key policy")

	var orphanQueue *goque.Queue
	if c.CA.OrphanQueueDir != "" {
		orphanQueue, err = goque.OpenQueue(c.CA.OrphanQueueDir)
		cmd.FailOnError(err, "Failed to open orphaned certificate queue")
		defer func() { _ = orphanQueue.Close() }()
	}

	cai, err := ca.NewCertificateAuthorityImpl(
		sa,
		pa,
		c.CA.CFSSL,
		c.CA.RSAProfile,
		c.CA.ECDSAProfile,
		cfsslIssuers,
		boulderIssuers,
		c.CA.Expiry.Duration,
		c.CA.Backdate.Duration,
		c.CA.SerialPrefix,
		c.CA.MaxNames,
		c.CA.LifespanOCSP.Duration,
		kp,
		orphanQueue,
		logger,
		scope,
		clk)
	cmd.FailOnError(err, "Failed to create CA impl")

	if orphanQueue != nil {
		go cai.OrphanIntegrationLoop()
	}

	serverMetrics := bgrpc.NewServerMetrics(scope)

	caSrv, caListener, err := bgrpc.NewServer(c.CA.GRPCCA, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup CA gRPC server")
	caWrapper := bgrpc.NewCertificateAuthorityServer(cai)
	capb.RegisterCertificateAuthorityServer(caSrv, caWrapper)
	caHealth := health.NewServer()
	healthpb.RegisterHealthServer(caSrv, caHealth)
	go func() {
		cmd.FailOnError(cmd.FilterShutdownErrors(caSrv.Serve(caListener)), "CA gRPC service failed")
	}()

	ocspSrv, ocspListener, err := bgrpc.NewServer(c.CA.GRPCOCSPGenerator, tlsConfig, serverMetrics, clk)
	cmd.FailOnError(err, "Unable to setup CA gRPC server")
	ocspWrapper := bgrpc.NewCertificateAuthorityServer(cai)
	capb.RegisterOCSPGeneratorServer(ocspSrv, ocspWrapper)
	ocspHealth := health.NewServer()
	healthpb.RegisterHealthServer(ocspSrv, ocspHealth)
	go func() {
		cmd.FailOnError(cmd.FilterShutdownErrors(ocspSrv.Serve(ocspListener)),
			"OCSPGenerator gRPC service failed")
	}()

	go cmd.CatchSignals(logger, func() {
		caHealth.Shutdown()
		ocspHealth.Shutdown()
		caSrv.GracefulStop()
		ocspSrv.GracefulStop()
	})

	select {}
}
