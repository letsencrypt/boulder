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
	"github.com/letsencrypt/boulder/db"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/issuercerts"
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
	// A list of issuer certificates. Orphaned certificates from the logs will be
	// matched against these when determining which issuer ID to enter into the
	// certificateStatus table.
	IssuerFiles []string
	Features    map[string]bool
}

type certificateStorage interface {
	AddSerial(context.Context, *sapb.AddSerialRequest) (*corepb.Empty, error)
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
	// certOrphanAlreadyExists indicates an orphaned final certificate that
	// already exists in the DB.
	certOrphanAlreadyExists
	// precertOrphanAlreadyExists indicates an orphaned precertificate that
	// already exists in the DB.
	precertOrphanAlreadyExists
)

// String returns a human representation of the orphanType.
// This is used both for printing orphanTypes and (in the case of certOrphan and
// precertOrphan) to figure out what to search for when parsing logs.
// Invalid orphanTypes are stringified as "unknown."
func (t orphanType) String() string {
	switch t {
	case certOrphan:
		return "certificate"
	case precertOrphan:
		return "precertificate"
	case certOrphanAlreadyExists:
		return "certificate (already exists in DB)"
	case precertOrphanAlreadyExists:
		return "precertificate (already exists in DB)"
	default:
		return "unknown"
	}
}

var (
	derOrphan        = regexp.MustCompile(`cert=\[([0-9a-f]+)\]`)
	regOrphan        = regexp.MustCompile(`regID=\[(\d+)\]`)
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
		if err == nil {
			return nil, certOrphanAlreadyExists, errAlreadyExists
		}
	case precertOrphan:
		_, err = sai.GetPrecertificate(ctx, &sapb.Serial{Serial: &orphanSerial})
		if err == nil {
			return nil, precertOrphanAlreadyExists, errAlreadyExists
		}
	default:
		return nil, unknownOrphan, errors.New("unknown orphan type")
	}
	if berrors.Is(err, berrors.NotFound) {
		return orphan, orphanTyp, nil
	}
	return nil, orphanTyp, fmt.Errorf("Existing %s lookup failed: %s", orphanTyp, err)
}

// storeParsedLogLine attempts to parse one log line according to the format used when
// orphaning certificates and precertificates. It returns two booleans and the
// orphanType: The first boolean is true if the line was a match, and the second
// is true if the orphan was successfully added to the DB. As part of adding an
// orphan to the DB, it requests a fresh OCSP response from the CA to store
// alongside the precertificate/certificate.
func (of *orphanFinder) storeParsedLogLine(line string) (found bool, added bool, typ orphanType) {
	ctx := context.Background()

	// The log line should contain a label indicating it is a cert or a precert
	// orphan. We will determine which it is in checkDER based on the DER instead
	// of the log line label.
	if !strings.Contains(line, fmt.Sprintf("orphaning %s", certOrphan)) &&
		!strings.Contains(line, fmt.Sprintf("orphaning %s", precertOrphan)) {
		return false, false, unknownOrphan
	}
	// The log line should also contain certificate DER
	if !strings.Contains(line, "cert=") {
		return false, false, unknownOrphan
	}
	// Extract and decode the orphan DER
	derStr := derOrphan.FindStringSubmatch(line)
	if len(derStr) <= 1 {
		of.logger.AuditErrf("Didn't match regex for cert: %s", line)
		return true, false, unknownOrphan
	}
	der, err := hex.DecodeString(derStr[1])
	if err != nil {
		of.logger.AuditErrf("Couldn't decode hex: %s, [%s]", err, line)
		return true, false, unknownOrphan
	}
	// extract the regID
	regStr := regOrphan.FindStringSubmatch(line)
	if len(regStr) <= 1 {
		of.logger.AuditErrf("regID variable is empty, [%s]", line)
		return true, false, typ
	}
	regID, err := strconv.ParseInt(regStr[1], 10, 64)
	if err != nil {
		of.logger.AuditErrf("Couldn't parse regID: %s, [%s]", err, line)
		return true, false, typ
	}

	typ, err = of.storeDER(ctx, regID, der)
	if err != nil {
		of.logger.AuditErrf("Failed to store certificate: %s, [%s]", err, line)
		return true, false, typ
	}
	if typ == certOrphanAlreadyExists || typ == precertOrphanAlreadyExists {
		return true, false, typ
	} else {
		return true, true, typ
	}
}

func (of *orphanFinder) findIssuerID(der []byte) (issuercerts.ID, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return 0, err
	}
	for _, issuer := range of.issuers {
		if err := cert.CheckSignatureFrom(issuer.Cert); err == nil {
			return issuer.ID(), nil
		}
	}
	return 0, fmt.Errorf("no issuer found")
}

func (of *orphanFinder) generateOCSP(ctx context.Context, certDER []byte) ([]byte, error) {
	// generate a fresh OCSP response
	statusGood := string(core.OCSPStatusGood)
	zeroInt32 := int32(0)
	zeroInt64 := int64(0)

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	issuerID, err := of.findIssuerID(certDER)
	if err != nil {
		return nil, err
	}
	issuerIDInt := int64(issuerID)

	serial := core.SerialToString(cert.SerialNumber)

	ocspResponse, err := of.ocspCA.GenerateOCSP(ctx, &capb.GenerateOCSPRequest{
		CertDER:   certDER,
		Status:    &statusGood,
		Reason:    &zeroInt32,
		RevokedAt: &zeroInt64,
		IssuerID:  &issuerIDInt,
		Serial:    &serial,
	})
	if err != nil {
		return nil, err
	}
	return ocspResponse.Response, nil
}

type orphanFinder struct {
	logger           blog.Logger
	sa               certificateStorage
	ocspCA           capb.OCSPGeneratorClient
	issuers          []*issuercerts.Issuer
	backdateDuration time.Duration
}

func setup(configFile string) (*orphanFinder, error) {
	configJSON, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("reading config: %s", err)
	}

	var conf config
	err = json.Unmarshal(configJSON, &conf)
	if err != nil {
		return nil, fmt.Errorf("parsing config: %s", err)
	}

	err = features.Set(conf.Features)
	if err != nil {
		return nil, fmt.Errorf("setting feature flags: %s", err)
	}

	logger := cmd.NewLogger(conf.Syslog)

	tlsConfig, err := conf.TLS.Load()
	if err != nil {
		return nil, fmt.Errorf("loading TLS config: %s", err)
	}

	clientMetrics := bgrpc.NewClientMetrics(metrics.NoopRegisterer)
	saConn, err := bgrpc.ClientSetup(conf.SAService, tlsConfig, clientMetrics, cmd.Clock())
	if err != nil {
		return nil, fmt.Errorf("setting up SA connection: %s", err)
	}

	sac := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(saConn))
	caConn, err := bgrpc.ClientSetup(conf.OCSPGeneratorService, tlsConfig, clientMetrics, cmd.Clock())
	if err != nil {
		return nil, fmt.Errorf("setting up OCSP CA connection: %s", err)
	}

	cac := capb.NewOCSPGeneratorClient(caConn)

	issuers, err := loadIssuers(conf.IssuerFiles)
	if err != nil {
		return nil, err
	}

	return &orphanFinder{logger, sac, cac, issuers, conf.Backdate.Duration}, nil
}

func loadIssuers(filenames []string) ([]*issuercerts.Issuer, error) {
	var issuers []*issuercerts.Issuer
	for _, filename := range filenames {
		issuer, err := issuercerts.FromFile(filename)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %s", filename, err)
		}
		issuers = append(issuers, issuer)
	}
	return issuers, nil
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

	switch command {
	case "parse-ca-log":
		if *logPath == "" {
			usage()
		}

		orphanFinder, err := setup(*configFile)
		cmd.FailOnError(err, "setup")

		logData, err := ioutil.ReadFile(*logPath)
		cmd.FailOnError(err, "Failed to read log file")

		var certOrphansFound, certOrphansAdded, precertOrphansFound, precertOrphansAdded int64
		for _, line := range strings.Split(string(logData), "\n") {
			if line == "" {
				continue
			}
			found, added, typ := orphanFinder.storeParsedLogLine(line)
			var foundStat, addStat *int64
			switch typ {
			case certOrphan:
				foundStat = &certOrphansFound
				addStat = &certOrphansAdded
			case precertOrphan:
				foundStat = &precertOrphansFound
				addStat = &precertOrphansAdded
			default:
				orphanFinder.logger.Errf("Found orphan type %s", typ)
				continue
			}
			if found {
				*foundStat++
				if added {
					*addStat++
				}
			}
		}
		orphanFinder.logger.Infof("Found %d certificate orphans and added %d to the database", certOrphansFound, certOrphansAdded)
		orphanFinder.logger.Infof("Found %d precertificate orphans and added %d to the database", precertOrphansFound, precertOrphansAdded)

	case "parse-der":
		if *derPath == "" || *regID == 0 {
			usage()
		}

		orphanFinder, err := setup(*configFile)
		cmd.FailOnError(err, "setup")

		der, err := ioutil.ReadFile(*derPath)
		cmd.FailOnError(err, "Failed to read DER file")
		_, err = orphanFinder.storeDER(context.Background(), *regID, der)
		cmd.FailOnError(err, "storing DER")

	default:
		usage()
	}
}

func (of *orphanFinder) storeDER(ctx context.Context, regID int64, der []byte) (orphanType, error) {
	cert, typ, err := checkDER(of.sa, der)
	if err != nil {
		if err == errAlreadyExists {
			of.logger.Infof("%s", err)
			return typ, nil
		} else {
			return unknownOrphan, err
		}
	}
	// Because certificates are backdated we need to add the backdate duration
	// to find the true issued time.
	issuedDate := cert.NotBefore.Add(of.backdateDuration)
	issuedDateNanos := issuedDate.UnixNano()
	notAfter := cert.NotAfter.UnixNano()
	serial := core.SerialToString(cert.SerialNumber)

	// The CA's GenerateOCSP method will return error if the serial is not in the
	// serials table, so add it in case it doesn't exist (for instance this
	// happens during integration testing). However, if the serial already exists
	// ignore the error.
	_, err = of.sa.AddSerial(ctx, &sapb.AddSerialRequest{
		RegID:   &regID,
		Serial:  &serial,
		Created: &issuedDateNanos,
		Expires: &notAfter,
	})
	if err != nil && !db.IsDuplicate(err) {
		return unknownOrphan, err
	}

	response, err := of.generateOCSP(ctx, der)
	if err != nil {
		return unknownOrphan, fmt.Errorf("generating OCSP: %s", err)
	}

	switch typ {
	case certOrphan:
		_, err = of.sa.AddCertificate(ctx, der, regID, response, &issuedDate)
		if err != nil {
			return unknownOrphan, fmt.Errorf("adding certificate: %s", err)
		}
	case precertOrphan:
		issuerID, err := of.findIssuerID(der)
		cmd.FailOnError(err, "finding issuerID")
		issuerIDInt := int64(issuerID)
		_, err = of.sa.AddPrecertificate(ctx, &sapb.AddCertificateRequest{
			Der:      der,
			RegID:    &regID,
			Ocsp:     response,
			Issued:   &issuedDateNanos,
			IssuerID: &issuerIDInt,
		})
		if err != nil {
			return unknownOrphan, fmt.Errorf("adding precertificate: %s", err)
		}
	default:
		return unknownOrphan, errors.New("unknown orphan type")
	}
	return typ, nil
}
