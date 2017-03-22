package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log/syslog"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/sa"
)

const (
	good = "valid"
	bad  = "invalid"

	filenameLayout = "20060102"

	expectedValidityPeriod = time.Hour * 24 * 90
)

// For defense-in-depth in addition to using the PA & its hostnamePolicy to
// check domain names we also perform a check against the regex's from the
// forbiddenDomains array
var forbiddenDomainPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\s*$`),
	regexp.MustCompile(`\.mil$`),
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
	Problems []string `json:"problems,omitempty"`
}

/*
 * certDB is an interface collecting the gorp.DbMap functions that the
 * various parts of cert-checker rely on. Using this adapter shim allows tests to
 * swap out the dbMap implementation.
 */
type certDB interface {
	Select(i interface{}, query string, args ...interface{}) ([]interface{}, error)
	SelectOne(holder interface{}, query string, args ...interface{}) error
}

type certChecker struct {
	pa           core.PolicyAuthority
	dbMap        certDB
	certs        chan core.Certificate
	clock        clock.Clock
	rMu          *sync.Mutex
	issuedReport report
	checkPeriod  time.Duration
	stats        metrics.Statter
}

func newChecker(saDbMap certDB, clk clock.Clock, pa core.PolicyAuthority, period time.Duration) certChecker {
	c := certChecker{
		pa:          pa,
		dbMap:       saDbMap,
		certs:       make(chan core.Certificate, batchSize),
		rMu:         new(sync.Mutex),
		clock:       clk,
		checkPeriod: period,
	}
	c.issuedReport.Entries = make(map[string]reportEntry)

	return c
}

func (c *certChecker) getCerts(unexpiredOnly bool) error {
	c.issuedReport.end = c.clock.Now()
	c.issuedReport.begin = c.issuedReport.end.Add(-c.checkPeriod)

	args := map[string]interface{}{"issued": c.issuedReport.begin, "now": 0}
	if unexpiredOnly {
		now := c.clock.Now()
		args["now"] = now
	}
	var count int
	err := c.dbMap.SelectOne(
		&count,
		"SELECT count(*) FROM certificates WHERE issued >= :issued AND expires >= :now",
		args,
	)
	if err != nil {
		return err
	}

	// Retrieve certs in batches of 1000 (the size of the certificate channel)
	// so that we don't eat unnecessary amounts of memory and avoid the 16MB MySQL
	// packet limit.
	args["limit"] = batchSize
	args["lastSerial"] = ""
	for offset := 0; offset < count; {
		certs, err := sa.SelectCertificates(
			c.dbMap,
			"WHERE issued >= :issued AND expires >= :now AND serial > :lastSerial LIMIT :limit",
			args,
		)
		if err != nil {
			return err
		}
		for _, cert := range certs {
			c.certs <- cert
		}
		if len(certs) == 0 {
			break
		}
		args["lastSerial"] = certs[len(certs)-1].Serial
		offset += len(certs)
	}

	// Close channel so range operations won't block once the channel empties out
	close(c.certs)
	return nil
}

func (c *certChecker) processCerts(wg *sync.WaitGroup, badResultsOnly bool) {
	for cert := range c.certs {
		problems := c.checkCert(cert)
		valid := len(problems) == 0
		c.rMu.Lock()
		if !badResultsOnly || (badResultsOnly && !valid) {
			c.issuedReport.Entries[cert.Serial] = reportEntry{
				Valid:    valid,
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

func (c *certChecker) checkCert(cert core.Certificate) (problems []string) {
	// Check digests match
	if cert.Digest != core.Fingerprint256(cert.DER) {
		problems = append(problems, "Stored digest doesn't match certificate digest")
	}

	// Parse certificate
	parsedCert, err := x509.ParseCertificate(cert.DER)
	if err != nil {
		problems = append(problems, fmt.Sprintf("Couldn't parse stored certificate: %s", err))
	} else {
		// Check stored serial is correct
		storedSerial, err := core.StringToSerial(cert.Serial)
		if err != nil {
			problems = append(problems, "Stored serial is invalid")
		} else if parsedCert.SerialNumber.Cmp(storedSerial) != 0 {
			problems = append(problems, "Stored serial doesn't match certificate serial")
		}
		// Check we have the right expiration time
		if !parsedCert.NotAfter.Equal(cert.Expires) {
			problems = append(problems, "Stored expiration doesn't match certificate NotAfter")
		}
		// Check basic constraints are set
		if !parsedCert.BasicConstraintsValid {
			problems = append(problems, "Certificate doesn't have basic constraints set")
		}
		// Check the cert isn't able to sign other certificates
		if parsedCert.IsCA {
			problems = append(problems, "Certificate can sign other certificates")
		}
		// Check the cert has the correct validity period
		validityPeriod := parsedCert.NotAfter.Sub(parsedCert.NotBefore)
		if validityPeriod > expectedValidityPeriod {
			problems = append(problems, fmt.Sprintf("Certificate has a validity period longer than %s", expectedValidityPeriod))
		} else if validityPeriod < expectedValidityPeriod {
			problems = append(problems, fmt.Sprintf("Certificate has a validity period shorter than %s", expectedValidityPeriod))
		}
		// Check the stored issuance time isn't too far back/forward dated
		if parsedCert.NotBefore.Before(cert.Issued.Add(-6*time.Hour)) || parsedCert.NotBefore.After(cert.Issued.Add(6*time.Hour)) {
			problems = append(problems, "Stored issuance date is outside of 6 hour window of certificate NotBefore")
		}
		// Check CommonName is <= 64 characters
		if len(parsedCert.Subject.CommonName) > 64 {
			problems = append(
				problems,
				fmt.Sprintf("Certificate has common name >64 characters long (%d)", len(parsedCert.Subject.CommonName)),
			)
		}
		// Check that the PA is still willing to issue for each name in DNSNames + CommonName
		for _, name := range append(parsedCert.DNSNames, parsedCert.Subject.CommonName) {
			id := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: name}
			if err = c.pa.WillingToIssue(id); err != nil {
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
		if !reflect.DeepEqual(parsedCert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
			problems = append(problems, "Certificate has incorrect key usage extensions")
		}
	}
	return problems
}

type config struct {
	CertChecker struct {
		cmd.DBConfig
		cmd.HostnamePolicyConfig

		Workers             int
		ReportDirectoryPath string
		UnexpiredOnly       bool
		BadResultsOnly      bool
		CheckPeriod         cmd.ConfigDuration

		Features map[string]bool
	}

	PA cmd.PAConfig

	Statsd cmd.StatsdConfig

	Syslog cmd.SyslogConfig
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	workers := flag.Int("workers", runtime.NumCPU(), "The number of concurrent workers used to process certificates")
	badResultsOnly := flag.Bool("bad-results-only", false, "Only collect and display bad results")
	connect := flag.String("db-connect", "", "SQL URI if not provided in the configuration file")
	cp := flag.Duration("check-period", time.Hour*2160, "How far back to check")
	unexpiredOnly := flag.Bool("unexpired-only", false, "Only check currently unexpired certificates")

	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var config config
	err := cmd.ReadConfigFile(*configFile, &config)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(config.CertChecker.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	stats, err := metrics.NewStatter(config.Statsd.Server, config.Statsd.Prefix)
	cmd.FailOnError(err, "Failed to create StatsD client")
	syslogger, err := syslog.Dial("", "", syslog.LOG_INFO|syslog.LOG_LOCAL0, "")
	cmd.FailOnError(err, "Failed to dial syslog")
	logger, err := blog.New(syslogger, 0, 0)
	cmd.FailOnError(err, "Failed to construct logger")
	err = blog.Set(logger)
	cmd.FailOnError(err, "Failed to set audit logger")

	if *connect != "" {
		config.CertChecker.DBConnect = *connect
	}
	if *workers != 0 {
		config.CertChecker.Workers = *workers
	}
	config.CertChecker.UnexpiredOnly = *unexpiredOnly
	config.CertChecker.BadResultsOnly = *badResultsOnly
	config.CertChecker.CheckPeriod.Duration = *cp

	// Validate PA config and set defaults if needed
	cmd.FailOnError(config.PA.CheckChallenges(), "Invalid PA configuration")

	saDbURL, err := config.CertChecker.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	saDbMap, err := sa.NewDbMap(saDbURL, config.CertChecker.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Could not connect to database")
	go sa.ReportDbConnCount(saDbMap, metrics.NewStatsdScope(stats, "CertChecker"))

	pa, err := policy.New(config.PA.Challenges)
	cmd.FailOnError(err, "Failed to create PA")
	err = pa.SetHostnamePolicyFile(config.CertChecker.HostnamePolicyFile)
	cmd.FailOnError(err, "Failed to load HostnamePolicyFile")

	checker := newChecker(
		saDbMap,
		clock.Default(),
		pa,
		config.CertChecker.CheckPeriod.Duration,
	)
	fmt.Fprintf(os.Stderr, "# Getting certificates issued in the last %s\n", config.CertChecker.CheckPeriod)

	// Since we grab certificates in batches we don't want this to block, when it
	// is finished it will close the certificate channel which allows the range
	// loops in checker.processCerts to break
	go func() {
		err = checker.getCerts(config.CertChecker.UnexpiredOnly)
		cmd.FailOnError(err, "Batch retrieval of certificates failed")
	}()

	fmt.Fprintf(os.Stderr, "# Processing certificates using %d workers\n", config.CertChecker.Workers)
	wg := new(sync.WaitGroup)
	for i := 0; i < config.CertChecker.Workers; i++ {
		wg.Add(1)
		go func() {
			s := checker.clock.Now()
			checker.processCerts(wg, config.CertChecker.BadResultsOnly)
			stats.TimingDuration("certChecker.processingLatency", time.Since(s), 1.0)
		}()
	}
	wg.Wait()
	fmt.Fprintf(
		os.Stderr,
		"# Finished processing certificates, sample: %d, good: %d, bad: %d\n",
		len(checker.issuedReport.Entries),
		checker.issuedReport.GoodCerts,
		checker.issuedReport.BadCerts,
	)
	err = checker.issuedReport.dump()
	cmd.FailOnError(err, "Failed to dump results: %s\n")

}
