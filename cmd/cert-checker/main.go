package notmain

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/syslog"
	"os"
	"reflect"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
	zX509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/identifier"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/sa"
)

// For defense-in-depth in addition to using the PA & its hostnamePolicy to
// check domain names we also perform a check against the regex's from the
// forbiddenDomains array
var forbiddenDomainPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\s*$`),
	regexp.MustCompile(`\.local$`),
	regexp.MustCompile(`^localhost$`),
	regexp.MustCompile(`\.localhost$`),
}

func isForbiddenDomain(name string) (bool, string) {
	for _, r := range forbiddenDomainPatterns {
		if matches := r.FindAllStringSubmatch(name, -1); len(matches) > 0 {
			return true, r.String()
		}
	}
	return false, ""
}

var batchSize = 1000

type report struct {
	begin     time.Time
	end       time.Time
	GoodCerts int64                  `json:"good-certs"`
	BadCerts  int64                  `json:"bad-certs"`
	Entries   map[string]reportEntry `json:"entries"`
}

func (r *report) dump() error {
	content, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(content))
	return nil
}

type reportEntry struct {
	Valid    bool     `json:"valid"`
	DNSNames []string `json:"dnsNames"`
	Problems []string `json:"problems,omitempty"`
}

// certDB is an interface collecting the gorp.saDbMap functions that the various
// parts of cert-checker rely on. Using this adapter shim allows tests to swap
// out the saDbMap implementation.
type certDB interface {
	Select(i interface{}, query string, args ...interface{}) ([]interface{}, error)
	SelectNullInt(query string, args ...interface{}) (sql.NullInt64, error)
}

type certChecker struct {
	pa                          core.PolicyAuthority
	kp                          goodkey.KeyPolicy
	dbMap                       certDB
	certs                       chan core.Certificate
	clock                       clock.Clock
	rMu                         *sync.Mutex
	issuedReport                report
	checkPeriod                 time.Duration
	acceptableValidityDurations map[time.Duration]bool
}

func newChecker(saDbMap certDB, clk clock.Clock, pa core.PolicyAuthority, kp goodkey.KeyPolicy, period time.Duration, avd map[time.Duration]bool) certChecker {
	return certChecker{
		pa:                          pa,
		kp:                          kp,
		dbMap:                       saDbMap,
		certs:                       make(chan core.Certificate, batchSize),
		rMu:                         new(sync.Mutex),
		clock:                       clk,
		issuedReport:                report{Entries: make(map[string]reportEntry)},
		checkPeriod:                 period,
		acceptableValidityDurations: avd,
	}
}

func (c *certChecker) getCerts(unexpiredOnly bool) error {
	c.issuedReport.end = c.clock.Now()
	c.issuedReport.begin = c.issuedReport.end.Add(-c.checkPeriod)

	args := map[string]interface{}{"issued": c.issuedReport.begin, "now": 0}
	if unexpiredOnly {
		args["now"] = c.clock.Now()
	}

	sni, err := c.dbMap.SelectNullInt(
		"SELECT MIN(id) FROM certificates WHERE issued >= :issued AND expires >= :now",
		args,
	)
	if err != nil {
		return err
	}
	if !sni.Valid {
		// a nil response was returned by the DB, so return error and fail
		return errors.New("the SELECT query resulted in a NULL response from the DB")
	}

	initialID := sni.Int64
	if initialID > 0 {
		// decrement the initial ID so that we select below as we aren't using >=
		initialID -= 1
	}

	// Retrieve certs in batches of 1000 (the size of the certificate channel)
	// so that we don't eat unnecessary amounts of memory and avoid the 16MB MySQL
	// packet limit.
	args["limit"] = batchSize
	args["id"] = initialID
	for {
		certs, err := sa.SelectCertificates(
			c.dbMap,
			"WHERE id > :id AND issued >= :issued AND expires >= :now ORDER BY id LIMIT :limit",
			args,
		)
		if err != nil {
			return err
		}
		for _, cert := range certs {
			c.certs <- cert.Certificate
		}
		if len(certs) == 0 {
			break
		}
		lastCert := certs[len(certs)-1]
		args["id"] = lastCert.ID
		if lastCert.Issued.After(c.issuedReport.end) {
			break
		}
	}

	// Close channel so range operations won't block once the channel empties out
	close(c.certs)
	return nil
}

func (c *certChecker) processCerts(wg *sync.WaitGroup, badResultsOnly bool, ignoredLints map[string]bool) {
	for cert := range c.certs {
		dnsNames, problems := c.checkCert(cert, ignoredLints)
		valid := len(problems) == 0
		c.rMu.Lock()
		if !badResultsOnly || (badResultsOnly && !valid) {
			c.issuedReport.Entries[cert.Serial] = reportEntry{
				Valid:    valid,
				DNSNames: dnsNames,
				Problems: problems,
			}
		}
		c.rMu.Unlock()
		if !valid {
			atomic.AddInt64(&c.issuedReport.BadCerts, 1)
		} else {
			atomic.AddInt64(&c.issuedReport.GoodCerts, 1)
		}
	}
	wg.Done()
}

// Extensions that we allow in certificates
var allowedExtensions = map[string]bool{
	"1.3.6.1.5.5.7.1.1":       true, // Authority info access
	"2.5.29.35":               true, // Authority key identifier
	"2.5.29.19":               true, // Basic constraints
	"2.5.29.32":               true, // Certificate policies
	"2.5.29.31":               true, // CRL distribution points
	"2.5.29.37":               true, // Extended key usage
	"2.5.29.15":               true, // Key usage
	"2.5.29.17":               true, // Subject alternative name
	"2.5.29.14":               true, // Subject key identifier
	"1.3.6.1.4.1.11129.2.4.2": true, // SCT list
	"1.3.6.1.5.5.7.1.24":      true, // TLS feature
}

// For extensions that have a fixed value we check that it contains that value
var expectedExtensionContent = map[string][]byte{
	"1.3.6.1.5.5.7.1.24": {0x30, 0x03, 0x02, 0x01, 0x05}, // Must staple feature
}

// checkCert returns a list of DNS names in the certificate and a list of problems with the certificate.
func (c *certChecker) checkCert(cert core.Certificate, ignoredLints map[string]bool) ([]string, []string) {
	var dnsNames []string
	var problems []string
	// Check that the digests match.
	if cert.Digest != core.Fingerprint256(cert.DER) {
		problems = append(problems, "Stored digest doesn't match certificate digest")
	}
	// Parse the certificate.
	parsedCert, err := zX509.ParseCertificate(cert.DER)
	if err != nil {
		problems = append(problems, fmt.Sprintf("Couldn't parse stored certificate: %s", err))
	} else {
		dnsNames = parsedCert.DNSNames
		// Run zlint checks.
		results := zlint.LintCertificate(parsedCert)
		for name, res := range results.Results {
			if ignoredLints[name] || res.Status <= lint.Pass {
				continue
			}
			prob := fmt.Sprintf("zlint %s: %s", res.Status, name)
			if res.Details != "" {
				prob = fmt.Sprintf("%s %s", prob, res.Details)
			}
			problems = append(problems, prob)
		}
		// Check if stored serial is correct.
		storedSerial, err := core.StringToSerial(cert.Serial)
		if err != nil {
			problems = append(problems, "Stored serial is invalid")
		} else if parsedCert.SerialNumber.Cmp(storedSerial) != 0 {
			problems = append(problems, "Stored serial doesn't match certificate serial")
		}
		// Check that we have the correct expiration time.
		if !parsedCert.NotAfter.Equal(cert.Expires) {
			problems = append(problems, "Stored expiration doesn't match certificate NotAfter")
		}
		// Check if basic constraints are set.
		if !parsedCert.BasicConstraintsValid {
			problems = append(problems, "Certificate doesn't have basic constraints set")
		}
		// Check that the cert isn't able to sign other certificates.
		if parsedCert.IsCA {
			problems = append(problems, "Certificate can sign other certificates")
		}
		// Check that the cert has a valid validity period. The validity
		// period is computed inclusive of the whole final second indicated by
		// notAfter.
		validityDuration := parsedCert.NotAfter.Add(time.Second).Sub(parsedCert.NotBefore)
		_, ok := c.acceptableValidityDurations[validityDuration]
		if !ok {
			problems = append(problems, "Certificate has unacceptable validity period")
		}
		// Check that the stored issuance time isn't too far back/forward dated.
		if parsedCert.NotBefore.Before(cert.Issued.Add(-6*time.Hour)) || parsedCert.NotBefore.After(cert.Issued.Add(6*time.Hour)) {
			problems = append(problems, "Stored issuance date is outside of 6 hour window of certificate NotBefore")
		}
		// Check if the CommonName is <= 64 characters.
		if len(parsedCert.Subject.CommonName) > 64 {
			problems = append(
				problems,
				fmt.Sprintf("Certificate has common name >64 characters long (%d)", len(parsedCert.Subject.CommonName)),
			)
		}
		// Check that the PA is still willing to issue for each name in DNSNames
		// + CommonName.
		for _, name := range append(parsedCert.DNSNames, parsedCert.Subject.CommonName) {
			id := identifier.ACMEIdentifier{Type: identifier.DNS, Value: name}
			err = c.pa.WillingToIssueWildcards([]identifier.ACMEIdentifier{id})
			if err != nil {
				problems = append(problems, fmt.Sprintf("Policy Authority isn't willing to issue for '%s': %s", name, err))
			} else {
				// For defense-in-depth, even if the PA was willing to issue for a name
				// we double check it against a list of forbidden domains. This way even
				// if the hostnamePolicyFile malfunctions we will flag the forbidden
				// domain matches
				if forbidden, pattern := isForbiddenDomain(name); forbidden {
					problems = append(problems, fmt.Sprintf(
						"Policy Authority was willing to issue but domain '%s' matches "+
							"forbiddenDomains entry %q", name, pattern))
				}
			}
		}
		// Check the cert has the correct key usage extensions
		if !reflect.DeepEqual(parsedCert.ExtKeyUsage, []zX509.ExtKeyUsage{zX509.ExtKeyUsageServerAuth, zX509.ExtKeyUsageClientAuth}) {
			problems = append(problems, "Certificate has incorrect key usage extensions")
		}

		for _, ext := range parsedCert.Extensions {
			_, ok := allowedExtensions[ext.Id.String()]
			if !ok {
				problems = append(problems, fmt.Sprintf("Certificate contains an unexpected extension: %s", ext.Id))
			}
			expectedContent, ok := expectedExtensionContent[ext.Id.String()]
			if ok {
				if !bytes.Equal(ext.Value, expectedContent) {
					problems = append(problems, fmt.Sprintf("Certificate extension %s contains unexpected content: has %x, expected %x", ext.Id, ext.Value, expectedContent))
				}
			}
		}

		// Check that the cert has a good key. Note that this does not perform
		// checks which rely on external resources such as weak or blocked key
		// lists, or the list of blocked keys in the database. This only performs
		// static checks, such as against the RSA key size and the ECDSA curve.
		p, err := x509.ParseCertificate(cert.DER)
		if err != nil {
			problems = append(problems, fmt.Sprintf("Couldn't parse stored certificate: %s", err))
		}
		err = c.kp.GoodKey(context.Background(), p.PublicKey)
		if err != nil {
			problems = append(problems, fmt.Sprintf("Key Policy isn't willing to issue for public key: %s", err))
		}
	}
	return dnsNames, problems
}

type Config struct {
	CertChecker struct {
		DB cmd.DBConfig
		cmd.HostnamePolicyConfig

		Workers             int
		ReportDirectoryPath string
		UnexpiredOnly       bool
		BadResultsOnly      bool
		CheckPeriod         cmd.ConfigDuration

		// AcceptableValidityDurations is a list of durations which are
		// acceptable for certificates we issue.
		AcceptableValidityDurations []cmd.ConfigDuration

		// GoodKey is an embedded config stanza for the goodkey library. If this
		// is populated, the cert-checker will perform static checks against the
		// public keys in the certs it checks.
		GoodKey goodkey.Config

		// IgnoredLints is a list of zlint names. Any lint results from a lint in
		// the IgnoredLists list are ignored regardless of LintStatus level.
		IgnoredLints []string
		Features     map[string]bool
	}
	PA     cmd.PAConfig
	Syslog cmd.SyslogConfig
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var config Config
	err := cmd.ReadConfigFile(*configFile, &config)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(config.CertChecker.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	syslogger, err := syslog.Dial("", "", syslog.LOG_INFO|syslog.LOG_LOCAL0, "")
	cmd.FailOnError(err, "Failed to dial syslog")

	syslogLevel := int(syslog.LOG_INFO)
	if config.Syslog.SyslogLevel != 0 {
		syslogLevel = config.Syslog.SyslogLevel
	}
	logger, err := blog.New(syslogger, config.Syslog.StdoutLevel, syslogLevel)
	cmd.FailOnError(err, "Could not connect to Syslog")

	err = blog.Set(logger)
	cmd.FailOnError(err, "Failed to set audit logger")

	acceptableValidityDurations := make(map[time.Duration]bool)
	if len(config.CertChecker.AcceptableValidityDurations) > 0 {
		for _, entry := range config.CertChecker.AcceptableValidityDurations {
			acceptableValidityDurations[entry.Duration] = true
		}
	} else {
		// For backwards compatibility, assume only a single valid validity
		// period of exactly 90 days if none is configured.
		ninetyDays := (time.Hour * 24) * 90
		acceptableValidityDurations[ninetyDays] = true
	}

	// Validate PA config and set defaults if needed.
	cmd.FailOnError(config.PA.CheckChallenges(), "Invalid PA configuration")

	if config.CertChecker.GoodKey.WeakKeyFile != "" {
		cmd.Fail("cert-checker does not support checking against weak key files")
	}
	if config.CertChecker.GoodKey.BlockedKeyFile != "" {
		cmd.Fail("cert-checker does not support checking against blocked key files")
	}
	kp, err := goodkey.NewKeyPolicy(&config.CertChecker.GoodKey, nil)
	cmd.FailOnError(err, "Unable to create key policy")

	saDbMap, err := sa.InitWrappedDb(config.CertChecker.DB, prometheus.DefaultRegisterer, logger)
	cmd.FailOnError(err, "While initializing dbMap")

	checkerLatency := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "cert_checker_latency",
		Help: "Histogram of latencies a cert-checker worker takes to complete a batch",
	})
	prometheus.DefaultRegisterer.MustRegister(checkerLatency)

	pa, err := policy.New(config.PA.Challenges)
	cmd.FailOnError(err, "Failed to create PA")

	err = pa.SetHostnamePolicyFile(config.CertChecker.HostnamePolicyFile)
	cmd.FailOnError(err, "Failed to load HostnamePolicyFile")

	checker := newChecker(
		saDbMap,
		cmd.Clock(),
		pa,
		kp,
		config.CertChecker.CheckPeriod.Duration,
		acceptableValidityDurations,
	)
	fmt.Fprintf(os.Stderr, "# Getting certificates issued in the last %s\n", config.CertChecker.CheckPeriod)

	ignoredLintsMap := make(map[string]bool)
	for _, name := range config.CertChecker.IgnoredLints {
		ignoredLintsMap[name] = true
	}

	// Since we grab certificates in batches we don't want this to block, when it
	// is finished it will close the certificate channel which allows the range
	// loops in checker.processCerts to break
	go func() {
		err := checker.getCerts(config.CertChecker.UnexpiredOnly)
		cmd.FailOnError(err, "Batch retrieval of certificates failed")
	}()

	fmt.Fprintf(os.Stderr, "# Processing certificates using %d workers\n", config.CertChecker.Workers)
	wg := new(sync.WaitGroup)
	for i := 0; i < config.CertChecker.Workers; i++ {
		wg.Add(1)
		go func() {
			s := checker.clock.Now()
			checker.processCerts(wg, config.CertChecker.BadResultsOnly, ignoredLintsMap)
			checkerLatency.Observe(checker.clock.Since(s).Seconds())
		}()
	}
	wg.Wait()
	fmt.Fprintf(
		os.Stderr,
		"# Finished processing certificates, report length: %d, good: %d, bad: %d\n",
		len(checker.issuedReport.Entries),
		checker.issuedReport.GoodCerts,
		checker.issuedReport.BadCerts,
	)
	err = checker.issuedReport.dump()
	cmd.FailOnError(err, "Failed to dump results: %s\n")
}

func init() {
	cmd.RegisterCommand("cert-checker", main)
}
