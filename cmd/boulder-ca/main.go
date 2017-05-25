package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/pkcs11key"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/ca"
	caPB "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/policy"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

const clientName = "CA"

type config struct {
	CA cmd.CAConfig

	PA cmd.PAConfig

	Syslog cmd.SyslogConfig

	Common struct {
		// Path to a PEM-encoded copy of the issuer certificate.
		IssuerCert string
	}
}

func loadIssuers(c config) ([]ca.Issuer, error) {
	if c.CA.Key != nil {
		issuerConfig := *c.CA.Key
		issuerConfig.CertFile = c.Common.IssuerCert
		priv, cert, err := loadIssuer(issuerConfig)
		return []ca.Issuer{{
			Signer: priv,
			Cert:   cert,
		}}, err
	}
	var issuers []ca.Issuer
	for _, issuerConfig := range c.CA.Issuers {
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
	numSessions := issuerConfig.NumSessions
	if numSessions <= 0 {
		numSessions = 1
	}
	return pkcs11key.NewPool(numSessions, pkcs11Config.Module,
		pkcs11Config.TokenLabel, pkcs11Config.PIN, pkcs11Config.PrivateKeyLabel)
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

	err = features.Set(c.CA.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	scope, logger := cmd.StatsAndLogging(c.Syslog)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString(clientName))

	cmd.FailOnError(c.PA.CheckChallenges(), "Invalid PA configuration")

	pa, err := policy.New(c.PA.Challenges)
	cmd.FailOnError(err, "Couldn't create PA")

	if c.CA.HostnamePolicyFile == "" {
		cmd.FailOnError(fmt.Errorf("HostnamePolicyFile was empty."), "")
	}
	err = pa.SetHostnamePolicyFile(c.CA.HostnamePolicyFile)
	cmd.FailOnError(err, "Couldn't load hostname policy file")

	issuers, err := loadIssuers(c)
	cmd.FailOnError(err, "Couldn't load issuers")

	kp, err := goodkey.NewKeyPolicy(c.CA.WeakKeyFile)
	cmd.FailOnError(err, "Unable to create key policy")

	cai, err := ca.NewCertificateAuthorityImpl(
		c.CA,
		clock.Default(),
		scope,
		issuers,
		kp,
		logger)
	cmd.FailOnError(err, "Failed to create CA impl")
	cai.PA = pa

	var tls *tls.Config
	if c.CA.TLS.CertFile != nil {
		tls, err = c.CA.TLS.Load()
		cmd.FailOnError(err, "TLS config")
	}

	conn, err := bgrpc.ClientSetup(c.CA.SAService, tls, scope)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	cai.SA = bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(conn))

	var caSrv *grpc.Server
	if c.CA.GRPCCA != nil {
		s, l, err := bgrpc.NewServer(c.CA.GRPCCA, tls, scope)
		cmd.FailOnError(err, "Unable to setup CA gRPC server")
		caWrapper := bgrpc.NewCertificateAuthorityServer(cai)
		caPB.RegisterCertificateAuthorityServer(s, caWrapper)
		go func() {
			err = s.Serve(l)
			cmd.FailOnError(err, "CA gRPC service failed")
		}()
		caSrv = s
	}
	var ocspSrv *grpc.Server
	if c.CA.GRPCOCSPGenerator != nil {
		s, l, err := bgrpc.NewServer(c.CA.GRPCOCSPGenerator, tls, scope)
		cmd.FailOnError(err, "Unable to setup CA gRPC server")
		caWrapper := bgrpc.NewCertificateAuthorityServer(cai)
		caPB.RegisterOCSPGeneratorServer(s, caWrapper)
		go func() {
			err = s.Serve(l)
			cmd.FailOnError(err, "OCSPGenerator gRPC service failed")
		}()
		ocspSrv = s
	}

	go cmd.CatchSignals(logger, func() {
		if caSrv != nil {
			caSrv.GracefulStop()
		}
		if ocspSrv != nil {
			ocspSrv.GracefulStop()
		}
	})

	go cmd.DebugServer(c.CA.DebugAddr)
	go cmd.ProfileCmd(scope)

	select {}
}
