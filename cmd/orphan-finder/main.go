package main

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	capb "github.com/letsencrypt/boulder/ca/proto"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"google.golang.org/grpc"
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
	TLS                  cmd.TLSConfig
	SAService            *cmd.GRPCClientConfig
	OCSPGeneratorService *cmd.GRPCClientConfig
	Syslog               cmd.SyslogConfig
	// Backdate specifies how to adjust a certificate's NotBefore date to get back
	// to the original issued date. It should match the value used in
	// `test/config/ca.json` for the CA "backdate" value.
	Backdate cmd.ConfigDuration
	Features map[string]bool
}

type certificateStorage interface {
	AddCertificate(context.Context, []byte, int64, []byte, *time.Time) (string, error)
	AddPrecertificate(ctx context.Context, req *sapb.AddCertificateRequest) (*corepb.Empty, error)
	GetCertificate(ctx context.Context, serial string) (core.Certificate, error)
	GetPrecertificate(ctx context.Context, reqSerial *sapb.Serial) (*corepb.Certificate, error)
}

type ocspGenerator interface {
	GenerateOCSP(context.Context, *capb.GenerateOCSPRequest, ...grpc.CallOption) (*capb.OCSPResponse, error)
}

// orphanType is a numeric identifier for the type of orphan being processed.
type orphanType int

const (
	// unknownOrphan indicates an orphan of an unknown type
	unknownOrphan orphanType = iota
	// certOrphan indicates an orphaned final certificate type
	certOrphan
	// precertOrphan indicates an orphaned precertificate type
	precertOrphan
)

// String returns a human representation of the orphanType and the expected
// label in the orphaning message for that type, or "unknown" if it isn't
// a known orphan type.
func (t orphanType) String() string {
	switch t {
	case certOrphan:
		return "certificate"
	case precertOrphan:
		return "precertificate"
	default:
		return "unknown"
	}
}

// An orphaned cert log line must contain at least the following tokens:
// "orphaning", "(pre)?certificate", "cert=[\w+]", "issuerID=[\d+]", and "regID=[\d]".
// For example:
// `[AUDIT] Failed RPC to store at SA, orphaning precertificate: serial=[04asdf1234], cert=[MIIdeafbeef], issuerID=[112358], regID=[1001], orderID=[1002], err=[Timed out]`
// The orphan-finder does not care about the serial, error, or orderID.
type parsedLine struct {
	certDER  []byte
	issuerID int64
	regID    int64
}

var (
	derOrphan        = regexp.MustCompile(`cert=\[([0-9a-f]+)\]`)
	regOrphan        = regexp.MustCompile(`regID=\[(\d+)\]`)
	issuerOrphan     = regexp.MustCompile(`issuerID=\[(\d+)\]`)
	errAlreadyExists = fmt.Errorf("Certificate already exists in DB")
)

// orphanTypeForCert returns precertOrphan if the certificate has the RFC 6962
// CT poison extension, or certOrphan if it does not. If the certificate is nil
// unknownOrphan is returned.
func orphanTypeForCert(cert *x509.Certificate) orphanType {
	if cert == nil {
		return unknownOrphan
	}
	// RFC 6962 Section 3.1 - https://tools.ietf.org/html/rfc6962#section-3.1
	poisonExt := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(poisonExt) {
			return precertOrphan
		}
	}
	return certOrphan
}

// checkDER parses the provided DER bytes and uses the resulting certificate's
// serial to check if there is an existing precertificate or certificate for the
// provided DER. If there is a matching precert/cert serial then
// errAlreadyExists and the orphanType are returned. If there is no matching
// precert/cert serial then the parsed certificate and orphanType are returned.
func checkDER(sai certificateStorage, der []byte) (*x509.Certificate, orphanType, error) {
	ctx := context.Background()
	orphan, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, unknownOrphan, fmt.Errorf("Failed to parse orphan DER: %s", err)
	}
	orphanSerial := core.SerialToString(orphan.SerialNumber)
	orphanTyp := orphanTypeForCert(orphan)

	switch orphanTyp {
	case certOrphan:
		_, err = sai.GetCertificate(ctx, orphanSerial)
	case precertOrphan:
		_, err = sai.GetPrecertificate(ctx, &sapb.Serial{Serial: orphanSerial})
	default:
		err = errors.New("unknown orphan type")
	}
	if err == nil {
		return nil, orphanTyp, errAlreadyExists
	}
	if errors.Is(err, berrors.NotFound) {
		return orphan, orphanTyp, nil
	}
	return nil, orphanTyp, fmt.Errorf("Existing %s lookup failed: %s", orphanTyp, err)
}

func parseLogLine(line string, logger blog.Logger) (parsedLine, error) {
	derStr := derOrphan.FindStringSubmatch(line)
	if len(derStr) <= 1 {
		return parsedLine{}, fmt.Errorf("unable to find cert der: %s", line)
	}
	der, err := hex.DecodeString(derStr[1])
	if err != nil {
		return parsedLine{}, fmt.Errorf("unable to decode hex der from [%s]: %s", line, err)
	}

	regStr := regOrphan.FindStringSubmatch(line)
	if len(regStr) <= 1 {
		return parsedLine{}, fmt.Errorf("unable to find regID: %s", line)
	}
	regID, err := strconv.ParseInt(regStr[1], 10, 64)
	if err != nil {
		return parsedLine{}, fmt.Errorf("unable to parse regID from [%s]: %s", line, err)
	}

	issuerStr := issuerOrphan.FindStringSubmatch(line)
	if len(issuerStr) <= 1 {
		return parsedLine{}, fmt.Errorf("unable to find issuerID: %s", line)
	}
	issuerID, err := strconv.ParseInt(issuerStr[1], 10, 64)
	if err != nil {
		return parsedLine{}, fmt.Errorf("unable to parse issuerID from [%s]: %s", line, err)
	}

	return parsedLine{
		certDER:  der,
		regID:    regID,
		issuerID: issuerID,
	}, nil
}

func generateOCSP(ctx context.Context, ca ocspGenerator, certDER []byte) ([]byte, error) {
	// generate a fresh OCSP response
	ocspResponse, err := ca.GenerateOCSP(ctx, &capb.GenerateOCSPRequest{
		CertDER:   certDER,
		Status:    string(core.OCSPStatusGood),
		Reason:    0,
		RevokedAt: 0,
	})
	if err != nil {
		return nil, err
	}
	return ocspResponse.Response, nil
}

type orphanFinder struct {
	sa       certificateStorage
	ca       ocspGenerator
	logger   blog.Logger
	backdate time.Duration
}

func newOrphanFinder(configFile string) *orphanFinder {
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

	clientMetrics := bgrpc.NewClientMetrics(metrics.NoopRegisterer)
	saConn, err := bgrpc.ClientSetup(conf.SAService, tlsConfig, clientMetrics, cmd.Clock())
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(saConn))

	caConn, err := bgrpc.ClientSetup(conf.OCSPGeneratorService, tlsConfig, clientMetrics, cmd.Clock())
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to CA")
	cac := capb.NewOCSPGeneratorClient(caConn)

	return &orphanFinder{
		sa:       sac,
		ca:       cac,
		logger:   logger,
		backdate: conf.Backdate.Duration,
	}
}

// parseCALog reads a log file, and attempts to parse and store any orphans from
// each line of it. It outputs stats about how many cert and precert orphans it
// found, and how many it successfully stored.
func (opf *orphanFinder) parseCALog(logPath string) {
	logData, err := ioutil.ReadFile(logPath)
	cmd.FailOnError(err, "Failed to read log file")

	var certOrphansFound, certOrphansAdded, precertOrphansFound, precertOrphansAdded int64
	for _, line := range strings.Split(string(logData), "\n") {
		if line == "" {
			continue
		}
		found, added, typ := opf.storeLogLine(line)
		var foundStat, addStat *int64
		switch typ {
		case certOrphan:
			foundStat = &certOrphansFound
			addStat = &certOrphansAdded
		case precertOrphan:
			foundStat = &precertOrphansFound
			addStat = &precertOrphansAdded
		default:
			opf.logger.Errf("Found orphan type %s", typ)
			continue
		}
		if found {
			*foundStat++
			if added {
				*addStat++
			}
		}
	}
	opf.logger.Infof("Found %d certificate orphans and added %d to the database", certOrphansFound, certOrphansAdded)
	opf.logger.Infof("Found %d precertificate orphans and added %d to the database", precertOrphansFound, precertOrphansAdded)
}

// storeLogLine attempts to parse one log line according to the format used when
// orphaning certificates and precertificates. It returns two booleans and the
// orphanType: The first boolean is true if the line was a match, and the second
// is true if the orphan was successfully added to the DB. As part of adding an
// orphan to the DB, it requests a fresh OCSP response from the CA to store
// alongside the precertificate/certificate.
func (opf *orphanFinder) storeLogLine(line string) (found bool, added bool, typ orphanType) {
	// At a minimum, the log line should contain the word "orphaning" and the token
	// "cert=". If it doesn't have those, short-circuit.
	if (!strings.Contains(line, fmt.Sprintf("orphaning %s", certOrphan)) &&
		!strings.Contains(line, fmt.Sprintf("orphaning %s", precertOrphan))) ||
		!strings.Contains(line, "cert=") {
		return false, false, unknownOrphan
	}

	parsed, err := parseLogLine(line, opf.logger)
	if err != nil {
		opf.logger.AuditErr(fmt.Sprintf("Couldn't parse log line: %s", err))
		return true, false, unknownOrphan
	}

	// Parse the DER, determine the orphan type, and ensure it doesn't already
	// exist in the DB
	cert, typ, err := checkDER(opf.sa, parsed.certDER)
	if err != nil {
		logFunc := opf.logger.Errf
		if err == errAlreadyExists {
			logFunc = opf.logger.Infof
		}
		logFunc("%s, [%s]", err, line)
		return true, false, typ
	}

	// generate an OCSP response
	ctx := context.Background()
	response, err := generateOCSP(ctx, opf.ca, parsed.certDER)
	if err != nil {
		opf.logger.AuditErrf("Couldn't generate OCSP: %s, [%s]", err, line)
		return true, false, typ
	}

	// We use `cert.NotBefore` as the issued date to avoid the SA tagging this
	// certificate with an issued date of the current time when we know it was an
	// orphan issued in the past. Because certificates are backdated we need to
	// add the backdate duration to find the true issued time.
	issuedDate := cert.NotBefore.Add(opf.backdate)
	switch typ {
	case certOrphan:
		_, err = opf.sa.AddCertificate(ctx, parsed.certDER, parsed.regID, response, &issuedDate)
	case precertOrphan:
		_, err = opf.sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
			Der:      parsed.certDER,
			RegID:    parsed.regID,
			Ocsp:     response,
			Issued:   issuedDate.UnixNano(),
			IssuerID: parsed.issuerID,
		})
	default:
		// Shouldn't happen but be defensive anyway
		err = errors.New("unknown orphan type")
	}
	if err != nil {
		opf.logger.AuditErrf("Failed to store certificate: %s, [%s]", err, line)
		return true, false, typ
	}
	return true, true, typ
}

// parseDER loads and attempts to store a single orphan from a single DER file.
func (opf *orphanFinder) parseDER(derPath string, regID int64) {
	der, err := ioutil.ReadFile(derPath)
	cmd.FailOnError(err, "Failed to read DER file")
	cert, typ, err := checkDER(opf.sa, der)
	cmd.FailOnError(err, "Pre-AddCertificate checks failed")
	// Because certificates are backdated we need to add the backdate duration
	// to find the true issued time.
	issuedDate := cert.NotBefore.Add(1 * opf.backdate)
	ctx := context.Background()
	response, err := generateOCSP(ctx, opf.ca, der)
	cmd.FailOnError(err, "Generating OCSP")

	switch typ {
	case certOrphan:
		_, err = opf.sa.AddCertificate(ctx, der, regID, response, &issuedDate)
	case precertOrphan:
		issued := issuedDate.UnixNano()
		_, err = opf.sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
			Der:    der,
			RegID:  regID,
			Ocsp:   response,
			Issued: issued,
		})
	default:
		err = errors.New("unknown orphan type")
	}
	cmd.FailOnError(err, "Failed to add certificate to database")
}

func main() {
	if len(os.Args) <= 2 {
		fmt.Fprint(os.Stderr, usageString)
		os.Exit(1)
	}

	command := os.Args[1]
	flagSet := flag.NewFlagSet(command, flag.ContinueOnError)
	configFile := flagSet.String("config", "", "File path to the configuration file for this service")
	logPath := flagSet.String("log-file", "", "Path to boulder-ca log file to parse")
	derPath := flagSet.String("der-file", "", "Path to DER certificate file")
	regID := flagSet.Int64("regID", 0, "Registration ID of user who requested the certificate")
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

	opf := newOrphanFinder(*configFile)

	switch command {
	case "parse-ca-log":
		if *logPath == "" {
			usage()
		}
		opf.parseCALog(*logPath)
	case "parse-der":
		if *derPath == "" || *regID == 0 {
			usage()
		}
		opf.parseDER(*derPath, *regID)
	default:
		usage()
	}
}
