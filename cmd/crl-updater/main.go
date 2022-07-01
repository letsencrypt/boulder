package notmain

import (
	"flag"
	"os"

	"github.com/honeycombio/beeline-go"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/crl/updater"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuance"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type Config struct {
	CRLUpdater struct {
		cmd.ServiceConfig

		CRLGeneratorService *cmd.GRPCClientConfig
		SAService           *cmd.GRPCClientConfig
		// TODO(#6162): Add this so we can talk to the crl-storer.
		// CRLStorerService    *cmd.GRPCClientConfig

		// IssuerCerts is a list of paths to issuer certificates on disk. This
		// controls the set of CRLs which will be published by this updater: it will
		// publish one set of NumShards CRL shards for each issuer in this list.
		IssuerCerts []string
		// NumShards is the number of shards into which each issuer's "full and
		// complete" CRL will be split.
		// WARNING: When this number is changed, the "JSON Array of CRL URLs" field
		// in CCADB MUST be updated.
		NumShards int64
		// LookbackPeriod controls how far into the past the updater should look.
		// You'd think that this could be 0, because certs are sharded by their
		// expiration time, and once a cert is expired, we don't have to care about
		// it anymore. But in fact, we do: as per RFC5280 Section 3.3 "An entry MUST
		// NOT be removed from the CRL until it appears on one regularly scheduled
		// CRL issued beyond the revoked certificate's validity period." Therefore
		// the LookbackPeriod MUST be at least the UpdatePeriod; a value of 2x or
		// more is recommended.
		// TODO: Consider removing this config parameter and instead computing it
		// directly as a function of UpdatePeriod.
		LookbackPeriod cmd.ConfigDuration
		// LookforwardPeriod controls how far into the future the updater should
		// look. This must be at least equal to the lifetime of the longest-lived
		// currently-valid certificate (generally 90d) *plus* the width of one
		// shard ((LookbackPeriod + LookforwardPeriod) / NumShards). Therefore,
		// a LookforwardPeriod of 100 days is recommended.
		// TODO: Consider removing this config parameter, replacing it with e.g.
		// `CertificateLifetime` (90d), and computing it from that and NumShards.
		LookforwardPeriod cmd.ConfigDuration
		// UpdatePeriod controls how frequently the crl-updater runs and publishes
		// new versions of every crl shard. The Baseline Requirements, Section 4.9.7
		// state that this MUST NOT be more than 7 days. We believe that future
		// updates may require that this not be more than 24 hours, and currently
		// recommend and UpdatePeriod of 6 hours.
		UpdatePeriod cmd.ConfigDuration

		Features map[string]bool
	}

	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig
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

	err = features.Set(c.CRLUpdater.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	tlsConfig, err := c.CRLUpdater.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.CRLUpdater.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())
	clk := cmd.Clock()

	bc, err := c.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

	issuers := make([]*issuance.Certificate, 0, len(c.CRLUpdater.IssuerCerts))
	for _, filepath := range c.CRLUpdater.IssuerCerts {
		cert, err := issuance.LoadCertificate(filepath)
		cmd.FailOnError(err, "Failed to load issuer cert")
		issuers = append(issuers, cert)
	}

	clientMetrics := bgrpc.NewClientMetrics(scope)

	caConn, err := bgrpc.ClientSetup(c.CRLUpdater.CRLGeneratorService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to CRLGenerator")
	cac := capb.NewCRLGeneratorClient(caConn)

	saConn, err := bgrpc.ClientSetup(c.CRLUpdater.SAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := sapb.NewStorageAuthorityClient(saConn)

	// TODO(#6162): Add this so we can talk to the crl-storer.
	// csConn, err := bgrpc.ClientSetup(c.CRLUpdater.CRLStorerService, tlsConfig, clientMetrics, clk)
	// cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to CRLStorer")
	// csc := cspb.NewCRLStorerClient(csConn)

	u, err := updater.NewUpdater(
		issuers,
		c.CRLUpdater.NumShards,
		c.CRLUpdater.LookbackPeriod.Duration,
		c.CRLUpdater.LookforwardPeriod.Duration,
		c.CRLUpdater.UpdatePeriod.Duration,
		sac,
		cac,
		scope,
		logger,
		clk,
	)
	cmd.FailOnError(err, "Failed to create crl-updater")

	go cmd.CatchSignals(logger, nil)
	u.Run()
}

func init() {
	cmd.RegisterCommand("crl-updater", main)
}
