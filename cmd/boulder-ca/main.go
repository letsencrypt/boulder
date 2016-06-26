package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	cfsslConfig "github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/pkcs11key"

	"github.com/letsencrypt/boulder/ca"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/goodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/policy"
	pubPB "github.com/letsencrypt/boulder/publisher/proto"
	"github.com/letsencrypt/boulder/rpc"
)

const clientName = "CA"

type config struct {
	// CAConfig structs have configuration information for the certificate
	// authority, including database parameters as well as controls for
	// issued certificates.
	CA struct {
		cmd.ServiceConfig
		cmd.DBConfig
		cmd.HostnamePolicyConfig

		RSAProfile   string
		ECDSAProfile string
		TestMode     bool
		SerialPrefix int
		// TODO(jsha): Remove Key field once we've migrated to Issuers
		Key *cmd.IssuerConfig
		// Issuers contains configuration information for each issuer cert and key
		// this CA knows about. The first in the list is used as the default.
		Issuers []cmd.IssuerConfig
		// LifespanOCSP is how long OCSP responses are valid for; It should be longer
		// than the minTimeToExpiry field for the OCSP Updater.
		LifespanOCSP cmd.ConfigDuration
		// How long issued certificates are valid for, should match expiry field
		// in cfssl config.
		Expiry string
		// The maximum number of subjectAltNames in a single certificate
		MaxNames int
		CFSSL    cfsslConfig.Config

		MaxConcurrentRPCServerRequests int64

		// DoNotForceCN is a temporary config setting. It controls whether
		// to add a certificate's serial to its Subject, and whether to
		// not pull a SAN entry to be the CN if no CN was given in a CSR.
		DoNotForceCN bool

		// EnableMustStaple governs whether the Must Staple extension in CSRs
		// triggers issuance of certificates with Must Staple.
		EnableMustStaple bool

		PublisherService *cmd.GRPCClientConfig
	}

	*cmd.AllowedSigningAlgos

	PA cmd.PAConfig

	cmd.StatsdConfig

	cmd.SyslogConfig

	Common struct {
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

func loadIssuers(cfg config) ([]ca.Issuer, error) {
	if cfg.CA.Key != nil {
		issuerConfig := *cfg.CA.Key
		issuerConfig.CertFile = cfg.Common.IssuerCert
		priv, cert, err := loadIssuer(issuerConfig)
		return []ca.Issuer{{
			Signer: priv,
			Cert:   cert,
		}}, err
	}
	var issuers []ca.Issuer
	for _, issuerConfig := range cfg.CA.Issuers {
		priv, cert, err := loadIssuer(issuerConfig)
		cmd.FailOnError(err, "Couldn't load private key")
		issuers = append(issuers, ca.Issuer{
			Signer: priv,
			Cert:   cert,
		})
	}
	return issuers, nil
}

func loadIssuer(issuerConfig cmd.IssuerConfig) (crypto.Signer, *x509.Certificate, error) {
	cert, err := core.LoadCert(issuerConfig.CertFile)
	if err != nil {
		return nil, nil, err
	}

	signer, err := loadSigner(issuerConfig)
	if err != nil {
		return nil, nil, err
	}

	if !core.KeyDigestEquals(signer.Public(), cert.PublicKey) {
		return nil, nil, fmt.Errorf("Issuer key did not match issuer cert %s", issuerConfig.CertFile)
	}
	return signer, cert, err
}

func loadSigner(issuerConfig cmd.IssuerConfig) (crypto.Signer, error) {
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
		pkcs11Config.PIN == "" ||
		pkcs11Config.PrivateKeyLabel == "" {
		return nil, fmt.Errorf("Missing a field in pkcs11Config %#v", pkcs11Config)
	}
	return pkcs11key.New(pkcs11Config.Module,
		pkcs11Config.TokenLabel, pkcs11Config.PIN, pkcs11Config.PrivateKeyLabel)
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var cfg config
	err := cmd.ReadJSONFile(*configFile, &cfg)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	cmd.FailOnError(cfg.PA.CheckChallenges(), "Invalid PA configuration")

	stats, logger := cmd.StatsAndLogging(cfg.StatsdConfig, cfg.SyslogConfig)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString(clientName))

	go cmd.DebugServer(cfg.CA.DebugAddr)

	pa, err := policy.New(cfg.PA.Challenges)
	cmd.FailOnError(err, "Couldn't create PA")

	if cfg.CA.HostnamePolicyFile == "" {
		cmd.FailOnError(fmt.Errorf("HostnamePolicyFile was empty."), "")
	}
	err = pa.SetHostnamePolicyFile(cfg.CA.HostnamePolicyFile)
	cmd.FailOnError(err, "Couldn't load hostname policy file")

	issuers, err := loadIssuers(cfg)
	cmd.FailOnError(err, "Couldn't load issuers")

	cai, err := ca.NewCertificateAuthorityImpl(
		cfg.CA,
		clock.Default(),
		stats,
		issuers,
		cfg.KeyPolicy(),
		logger)
	cmd.FailOnError(err, "Failed to create CA impl")
	cai.PA = pa

	go cmd.ProfileCmd("CA", stats)

	amqpConf := cfg.CA.AMQP
	cai.SA, err = rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
	cmd.FailOnError(err, "Failed to create SA client")

	if cfg.CA.PublisherService != nil {
		conn, err := bgrpc.ClientSetup(cfg.CA.PublisherService)
		cmd.FailOnError(err, "Failed to load credentials and create connection to service")
		cai.Publisher = bgrpc.NewPublisherClientWrapper(pubPB.NewPublisherClient(conn), cfg.CA.PublisherService.Timeout.Duration)
	} else {
		cai.Publisher, err = rpc.NewPublisherClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Failed to create Publisher client")
	}

	cas, err := rpc.NewAmqpRPCServer(amqpConf, cfg.CA.MaxConcurrentRPCServerRequests, stats, logger)
	cmd.FailOnError(err, "Unable to create CA RPC server")
	err = rpc.NewCertificateAuthorityServer(cas, cai)
	cmd.FailOnError(err, "Failed to create Certificate Authority RPC server")

	err = cas.Start(amqpConf)
	cmd.FailOnError(err, "Unable to run CA RPC server")
}
