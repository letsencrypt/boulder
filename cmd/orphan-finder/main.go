package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

var usageString = `
name:
  orphan-finder - Reads orphaned certificates from a boulder-ca log or a der file and adds them to the database

usage:
  orphan-finder parse-ca-log --config <path> --log-file <path>
  orphan-finder parse-der --config <path> --der-file <path> --regID <registration-id>

command descriptions:
  parse-ca-log    Parses boulder-ca logs to add multiple orphaned certificates
  parse-der       Parses a single orphaned DER certificate file and adds it to the database
`

type config struct {
	TLS       cmd.TLSConfig
	SAService *cmd.GRPCClientConfig
	Syslog    cmd.SyslogConfig
	// Backdate specifies how to adjust a certificate's NotBefore date to get back
	// to the original issued date. It should match the value used in
	// `test/config/ca.json` for the CA "backdate" value.
	Backdate cmd.ConfigDuration
	Features map[string]bool
}

type certificateStorage interface {
	AddCertificate(context.Context, []byte, int64, []byte, *time.Time) (string, error)
	GetCertificate(ctx context.Context, serial string) (core.Certificate, error)
}

var (
	derOrphan        = regexp.MustCompile(`cert=\[([0-9a-f]+)\]`)
	regOrphan        = regexp.MustCompile(`regID=\[(\d+)\]`)
	errAlreadyExists = fmt.Errorf("Certificate already exists in DB")
)

var backdateDuration time.Duration

func checkDER(sai certificateStorage, der []byte) (*x509.Certificate, error) {
	ctx := context.Background()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse DER: %s", err)
	}
	_, err = sai.GetCertificate(ctx, core.SerialToString(cert.SerialNumber))
	if err == nil {
		return nil, errAlreadyExists
	}
	if berrors.Is(err, berrors.NotFound) {
		return cert, nil
	}
	return nil, fmt.Errorf("Existing certificate lookup failed: %s", err)
}

func parseLogLine(sa certificateStorage, logger blog.Logger, line string) (found bool, added bool) {
	ctx := context.Background()
	if !strings.Contains(line, "cert=") || !strings.Contains(line, "orphaning certificate") {
		return false, false
	}
	derStr := derOrphan.FindStringSubmatch(line)
	if len(derStr) <= 1 {
		logger.AuditErr(fmt.Sprintf("Didn't match regex for cert: %s", line))
		return true, false
	}
	der, err := hex.DecodeString(derStr[1])
	if err != nil {
		logger.AuditErr(fmt.Sprintf("Couldn't decode hex: %s, [%s]", err, line))
		return true, false
	}
	cert, err := checkDER(sa, der)
	if err != nil {
		logFunc := logger.Err
		if err == errAlreadyExists {
			logFunc = logger.Info
		}
		logFunc(fmt.Sprintf("%s, [%s]", err, line))
		return true, false
	}
	// extract the regID
	regStr := regOrphan.FindStringSubmatch(line)
	if len(regStr) <= 1 {
		logger.AuditErr(fmt.Sprintf("regID variable is empty, [%s]", line))
		return true, false
	}
	regID, err := strconv.Atoi(regStr[1])
	if err != nil {
		logger.AuditErr(fmt.Sprintf("Couldn't parse regID: %s, [%s]", err, line))
		return true, false
	}
	// OCSP-Updater will do the first response generation for this cert so pass an
	// empty OCSP response. We use `cert.NotBefore` as the issued date to avoid
	// the SA tagging this certificate with an issued date of the current time
	// when we know it was an orphan issued in the past. Because certificates are
	// backdated we need to add the backdate duration to find the true issued
	// time.
	issuedDate := cert.NotBefore.Add(backdateDuration)
	_, err = sa.AddCertificate(ctx, der, int64(regID), nil, &issuedDate)
	if err != nil {
		logger.AuditErr(fmt.Sprintf("Failed to store certificate: %s, [%s]", err, line))
		return true, false
	}
	return true, true
}

func setup(configFile string) (blog.Logger, core.StorageAuthority) {
	configJSON, err := ioutil.ReadFile(configFile)
	cmd.FailOnError(err, "Failed to read config file")
	var conf config
	err = json.Unmarshal(configJSON, &conf)
	cmd.FailOnError(err, "Failed to parse config file")
	err = features.Set(conf.Features)
	cmd.FailOnError(err, "Failed to set feature flags")
	logger := cmd.NewLogger(conf.Syslog)

	tlsConfig, err := conf.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clientMetrics := bgrpc.NewClientMetrics(metrics.NewNoopScope())
	conn, err := bgrpc.ClientSetup(conf.SAService, tlsConfig, clientMetrics)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(conn))

	backdateDuration = conf.Backdate.Duration
	return logger, sac
}

func main() {
	if len(os.Args) <= 2 {
		fmt.Fprintf(os.Stderr, usageString)
		os.Exit(1)
	}

	command := os.Args[1]
	flagSet := flag.NewFlagSet(command, flag.ContinueOnError)
	configFile := flagSet.String("config", "", "File path to the configuration file for this service")
	logPath := flagSet.String("log-file", "", "Path to boulder-ca log file to parse")
	derPath := flagSet.String("der-file", "", "Path to DER certificate file")
	regID := flagSet.Int("regID", 0, "Registration ID of user who requested the certificate")
	err := flagSet.Parse(os.Args[2:])
	cmd.FailOnError(err, "Error parsing flagset")

	usage := func() {
		fmt.Fprintf(os.Stderr, "%s\nargs:", usageString)
		flagSet.PrintDefaults()
		os.Exit(1)
	}

	if *configFile == "" {
		usage()
	}

	switch command {
	case "parse-ca-log":
		logger, sa := setup(*configFile)
		if *logPath == "" {
			usage()
		}

		logData, err := ioutil.ReadFile(*logPath)
		cmd.FailOnError(err, "Failed to read log file")

		orphansFound := int64(0)
		orphansAdded := int64(0)
		for _, line := range strings.Split(string(logData), "\n") {
			found, added := parseLogLine(sa, logger, line)
			if found {
				orphansFound++
				if added {
					orphansAdded++
				}
			}
		}
		logger.Info(fmt.Sprintf("Found %d orphans and added %d to the database\n", orphansFound, orphansAdded))

	case "parse-der":
		ctx := context.Background()
		_, sa := setup(*configFile)
		if *derPath == "" || *regID == 0 {
			usage()
		}
		der, err := ioutil.ReadFile(*derPath)
		cmd.FailOnError(err, "Failed to read DER file")
		cert, err := checkDER(sa, der)
		cmd.FailOnError(err, "Pre-AddCertificate checks failed")
		// Because certificates are backdated we need to add the backdate duration
		// to find the true issued time.
		issuedDate := cert.NotBefore.Add(1 * backdateDuration)
		_, err = sa.AddCertificate(ctx, der, int64(*regID), nil, &issuedDate)
		cmd.FailOnError(err, "Failed to add certificate to database")

	default:
		usage()
	}
}
