package notmain

import (
	"context"
	"crypto/mldsa"
	"flag"
	"fmt"
	"os"

	"github.com/letsencrypt/boulder/blog"
	"github.com/letsencrypt/boulder/bs3"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/mtpublisher"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/cosigners"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/treedb"
)

type Config struct {
	MTPublisher struct {
		DB cmd.DBConfig

		DebugAddr string `validate:"omitempty,hostname_port"`

		// PollInterval is how often the publisher scans for checkpoints that
		// still lack a mirror cosignature.
		PollInterval config.Duration `validate:"required"`

		// LogID identifies the issuance log this publisher operates on. It must
		// match the mtca's.
		LogID issuancelog.Config `validate:"required"`

		// MTCACertFile holds the PEM-encoded certificate of the mtca, whose
		// ML-DSA-44 public key is used to reconstruct each checkpoint's signed
		// note from the database.
		MTCACertFile string `validate:"required"`

		// Cosigners is Chrome's cosigner list, which provides the mirrors to
		// submit to.
		Cosigners struct {
			// JSONFile holds https://www.gstatic.com/mtcs/cosigners/v1/cosigners.json
			// (schema: https://www.gstatic.com/mtcs/cosigners/v1/cosigners_schema.json).
			JSONFile string `validate:"required"`

			// PEMFile holds https://www.gstatic.com/mtcs/cosigners/v1/cosigners.pem,
			// the cosigners' public keys.
			PEMFile string `validate:"required"`

			// Realm is the realm of the mirrors to submit to, that of the
			// Chrome root store the CA is in: UNTRUSTED_VALIDATION_ONLY for
			// the test root store, PUBLICLY_TRUSTED for the production one.
			Realm cosigners.Realm `validate:"required"`
		}

		// MirrorTimeout bounds each request to a mirror.
		MirrorTimeout config.Duration `validate:"required"`

		// S3 locates the source log's tile storage, which the publisher reads
		// entries and proof hashes from when submitting to the mirror.
		S3 bs3.Config `validate:"required"`
	}
	Syslog        blog.Config
	OpenTelemetry cmd.OpenTelemetryConfig
}

func main() {
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

	if *debugAddr != "" {
		c.MTPublisher.DebugAddr = *debugAddr
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(
		cmd.SyslogConfig{StdoutLevel: c.Syslog.StdoutLevel, SyslogLevel: c.Syslog.SyslogLevel},
		c.OpenTelemetry, c.MTPublisher.DebugAddr)
	defer oTelShutdown(context.Background())
	cmd.LogStartup(logger)

	slogger := cmd.NewSlogger(c.Syslog)

	dbMap, err := sa.InitDB(c.MTPublisher.DB, scope, logger)
	cmd.FailOnError(err, "While initializing dbMap")

	s3c, err := bs3.FromConfig(c.MTPublisher.S3, logger)
	cmd.FailOnError(err, "Loading S3 config")

	caCert, err := issuance.LoadCertificate(c.MTPublisher.MTCACertFile)
	cmd.FailOnError(err, "Loading MTCA certificate")
	caPubKey, ok := caCert.PublicKey.(*mldsa.PublicKey)
	if !ok {
		cmd.Fail(fmt.Sprintf("MTCA certificate public key is %T, must be ML-DSA-44", caCert.PublicKey))
	}

	logID, err := c.MTPublisher.LogID.Load()
	cmd.FailOnError(err, "Parsing Log ID")

	caVerifier, err := cosignature.NewVerifier(logID.CAID(), caPubKey)
	cmd.FailOnError(err, "Creating MTCA verifier")

	cosignersJSON, err := os.ReadFile(c.MTPublisher.Cosigners.JSONFile)
	cmd.FailOnError(err, "Reading cosigners.json")
	cosignersPEM, err := os.ReadFile(c.MTPublisher.Cosigners.PEMFile)
	cmd.FailOnError(err, "Reading cosigners.pem")
	cosignerList, err := cosigners.Parse(cosignersJSON, cosignersPEM)
	cmd.FailOnError(err, "Parsing the cosigner list")
	realmMirrors, err := cosignerList.ForRealm(c.MTPublisher.Cosigners.Realm)
	cmd.FailOnError(err, "Selecting the mirrors for this realm")

	src := mtpublisher.NewSource(s3c, logID.TilePrefix())
	cosigningMirrors := realmMirrors.ForPurpose(cosigners.Cosigning, logID.CAID())
	if len(cosigningMirrors) == 0 {
		cmd.Fail(fmt.Sprintf("No mirror in realm %s is Usable and unaffiliated with CA %s", c.MTPublisher.Cosigners.Realm, logID.CAID()))
	}
	var cosigning []mtpublisher.Mirror
	for _, mirror := range cosigningMirrors {
		client, err := mtpublisher.NewMirrorClient(mirror.SubmissionPrefix, mirror.MonitoringPrefix, src, mirror.BaseID.String(), mirror.PublicKey, c.MTPublisher.MirrorTimeout.Duration)
		cmd.FailOnError(err, fmt.Sprintf("Creating client for mirror %s (%s)", mirror.BaseID, mirror.FriendlyName))
		cosigning = append(cosigning, client)
	}
	var submitOnly []mtpublisher.Mirror
	for _, mirror := range realmMirrors.ForPurpose(cosigners.SubmissionOnly, logID.CAID()) {
		client, err := mtpublisher.NewMirrorClient(mirror.SubmissionPrefix, mirror.MonitoringPrefix, src, mirror.BaseID.String(), mirror.PublicKey, c.MTPublisher.MirrorTimeout.Duration)
		cmd.FailOnError(err, fmt.Sprintf("Creating client for mirror %s (%s)", mirror.BaseID, mirror.FriendlyName))
		submitOnly = append(submitOnly, client)
	}

	publisher, err := mtpublisher.New(treedb.New(dbMap), c.MTPublisher.PollInterval.Duration, logID, caVerifier, cosigning, submitOnly, slogger)
	cmd.FailOnError(err, "Failed to create MTPublisher")

	ctx, cancel := context.WithCancel(context.Background())
	go cmd.CatchSignals(cancel)
	publisher.Start(ctx)
}

func init() {
	cmd.RegisterCommand("boulder-mtpublisher", main, &cmd.ConfigValidator{Config: &Config{}})
}
