package main

import (
	"bytes"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	netmail "net/mail"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/template"
	"time"

	"golang.org/x/net/context"

	"github.com/jmhodges/clock"
	"gopkg.in/go-gorp/gorp.v2"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	blog "github.com/letsencrypt/boulder/log"
	bmail "github.com/letsencrypt/boulder/mail"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	defaultNagCheckInterval  = 24 * time.Hour
	defaultExpirationSubject = "Let's Encrypt certificate expiration notice for domain {{.ExpirationSubject}}"
)

type regStore interface {
	GetRegistration(context.Context, int64) (core.Registration, error)
}

type mailer struct {
	log             blog.Logger
	dbMap           *gorp.DbMap
	rs              regStore
	mailer          bmail.Mailer
	emailTemplate   *template.Template
	subjectTemplate *template.Template
	nagTimes        []time.Duration
	limit           int
	clk             clock.Clock
	stats           mailerStats
}

type mailerStats struct {
	nagsAtCapacity    *prometheus.GaugeVec
	errorCount        *prometheus.CounterVec
	renewalCount      *prometheus.CounterVec
	sendLatency       prometheus.Histogram
	processingLatency prometheus.Histogram
}

func (m *mailer) sendNags(contacts []string, certs []*x509.Certificate) error {
	if len(contacts) == 0 {
		return nil
	}
	if len(certs) == 0 {
		return errors.New("no certs given to send nags for")
	}
	emails := []string{}
	for _, contact := range contacts {
		parsed, err := url.Parse(contact)
		if err != nil {
			m.log.AuditErrf("parsing contact email %s: %s", contact, err)
			continue
		}
		if parsed.Scheme == "mailto" {
			emails = append(emails, parsed.Opaque)
		}
	}
	if len(emails) == 0 {
		return nil
	}

	expiresIn := time.Duration(math.MaxInt64)
	expDate := m.clk.Now()
	domains := []string{}
	serials := []string{}

	// Pick out the expiration date that is closest to being hit.
	for _, cert := range certs {
		domains = append(domains, cert.DNSNames...)
		serials = append(serials, core.SerialToString(cert.SerialNumber))
		possible := cert.NotAfter.Sub(m.clk.Now())
		if possible < expiresIn {
			expiresIn = possible
			expDate = cert.NotAfter
		}
	}
	domains = core.UniqueLowerNames(domains)
	sort.Strings(domains)
	m.log.Debugf("Sending mail for %s (%s)", strings.Join(domains, ", "), strings.Join(serials, ", "))

	// Construct the information about the expiring certificates for use in the
	// subject template
	expiringSubject := fmt.Sprintf("%q", domains[0])
	if len(domains) > 1 {
		expiringSubject += fmt.Sprintf(" (and %d more)", len(domains)-1)
	}

	// Execute the subjectTemplate by filling in the ExpirationSubject
	subjBuf := new(bytes.Buffer)
	err := m.subjectTemplate.Execute(subjBuf, struct {
		ExpirationSubject string
	}{
		ExpirationSubject: expiringSubject,
	})
	if err != nil {
		m.stats.errorCount.With(prometheus.Labels{"type": "SubjectTemplateFailure"}).Inc()
		return err
	}

	email := struct {
		ExpirationDate   string
		DaysToExpiration int
		DNSNames         string
	}{
		ExpirationDate:   expDate.UTC().Format(time.RFC822Z),
		DaysToExpiration: int(expiresIn.Hours() / 24),
		DNSNames:         strings.Join(domains, "\n"),
	}
	msgBuf := new(bytes.Buffer)
	err = m.emailTemplate.Execute(msgBuf, email)
	if err != nil {
		m.stats.errorCount.With(prometheus.Labels{"type": "TemplateFailure"}).Inc()
		return err
	}
	startSending := m.clk.Now()
	err = m.mailer.SendMail(emails, subjBuf.String(), msgBuf.String())
	if err != nil {
		return err
	}
	finishSending := m.clk.Now()
	elapsed := finishSending.Sub(startSending)
	m.stats.sendLatency.Observe(elapsed.Seconds())
	return nil
}

func (m *mailer) updateCertStatus(serial string) error {
	_, err := m.dbMap.Exec(
		"UPDATE certificateStatus SET lastExpirationNagSent = ?  WHERE serial = ?",
		m.clk.Now(), serial)
	return err
}

func (m *mailer) certIsRenewed(serial string) (renewed bool, err error) {
	present, err := m.dbMap.SelectInt(`
		SELECT b.serial IS NOT NULL
		FROM fqdnSets a
		LEFT OUTER JOIN fqdnSets b
			ON a.setHash = b.setHash
			AND a.issued < b.issued
		WHERE a.serial = :serial
		LIMIT 1`,
		map[string]interface{}{"serial": serial},
	)
	if present == 1 {
		m.log.Debugf("Cert %s is already renewed", serial)
	}
	return present == 1, err
}

func (m *mailer) processCerts(allCerts []core.Certificate) {
	ctx := context.Background()

	regIDToCerts := make(map[int64][]core.Certificate)

	for _, cert := range allCerts {
		cs := regIDToCerts[cert.RegistrationID]
		cs = append(cs, cert)
		regIDToCerts[cert.RegistrationID] = cs
	}

	err := m.mailer.Connect()
	if err != nil {
		m.log.AuditErrf("Error connecting to send nag emails: %s", err)
		return
	}
	defer func() {
		_ = m.mailer.Close()
	}()

	for regID, certs := range regIDToCerts {
		reg, err := m.rs.GetRegistration(ctx, regID)
		if err != nil {
			m.log.AuditErrf("Error fetching registration %d: %s", regID, err)
			m.stats.errorCount.With(prometheus.Labels{"type": "GetRegistration"}).Inc()
			continue
		}

		parsedCerts := []*x509.Certificate{}
		for _, cert := range certs {
			parsedCert, err := x509.ParseCertificate(cert.DER)
			if err != nil {
				// TODO(#1420): tell registration about this error
				m.log.AuditErrf("Error parsing certificate %s: %s", cert.Serial, err)
				m.stats.errorCount.With(prometheus.Labels{"type": "ParseCertificate"}).Inc()
				continue
			}

			renewed, err := m.certIsRenewed(cert.Serial)
			if err != nil {
				m.log.AuditErrf("expiration-mailer: error fetching renewal state: %v", err)
				// assume not renewed
			} else if renewed {
				m.stats.renewalCount.With(prometheus.Labels{}).Inc()
				if err := m.updateCertStatus(cert.Serial); err != nil {
					m.log.AuditErrf("Error updating certificate status for %s: %s", cert.Serial, err)
					m.stats.errorCount.With(prometheus.Labels{"type": "UpdateCertificateStatus"}).Inc()
				}
				continue
			}

			parsedCerts = append(parsedCerts, parsedCert)
		}

		if len(parsedCerts) == 0 {
			// all certificates are renewed
			continue
		}

		if reg.Contact == nil {
			continue
		}

		err = m.sendNags(*reg.Contact, parsedCerts)
		if err != nil {
			m.stats.errorCount.With(prometheus.Labels{"type": "SendNags"}).Inc()
			m.log.AuditErrf("Error sending nag emails: %s", err)
			continue
		}
		for _, cert := range parsedCerts {
			serial := core.SerialToString(cert.SerialNumber)
			err = m.updateCertStatus(serial)
			if err != nil {
				m.log.AuditErrf("Error updating certificate status for %s: %s", serial, err)
				m.stats.errorCount.With(prometheus.Labels{"type": "UpdateCertificateStatus"}).Inc()
				continue
			}
		}
	}
	return
}

func (m *mailer) findExpiringCertificates() error {
	now := m.clk.Now()
	// E.g. m.nagTimes = [2, 4, 8, 15] days from expiration
	for i, expiresIn := range m.nagTimes {
		left := now
		if i > 0 {
			left = left.Add(m.nagTimes[i-1])
		}
		right := now.Add(expiresIn)

		m.log.Infof("expiration-mailer: Searching for certificates that expire between %s and %s and had last nag >%s before expiry",
			left.UTC(), right.UTC(), expiresIn)

		// First we do a query on the certificateStatus table to find certificates
		// nearing expiry meeting our criteria for email notification. We later
		// sequentially fetch the certificate details. This avoids an expensive
		// JOIN.
		var serials []string
		_, err := m.dbMap.Select(
			&serials,
			`SELECT
				cs.serial
				FROM certificateStatus AS cs
				WHERE cs.notAfter > :cutoffA
				AND cs.notAfter <= :cutoffB
				AND cs.status != "revoked"
				AND COALESCE(TIMESTAMPDIFF(SECOND, cs.lastExpirationNagSent, cs.notAfter) > :nagCutoff, 1)
				ORDER BY cs.notAfter ASC
				LIMIT :limit`,
			map[string]interface{}{
				"cutoffA":   left,
				"cutoffB":   right,
				"nagCutoff": expiresIn.Seconds(),
				"limit":     m.limit,
			},
		)
		if err != nil {
			m.log.AuditErrf("expiration-mailer: Error loading certificate serials: %s", err)
			return err
		}

		// Now we can sequentially retrieve the certificate details for each of the
		// certificate status rows
		var certs []core.Certificate
		for _, serial := range serials {
			var cert core.Certificate
			cert, err := sa.SelectCertificate(m.dbMap, "WHERE serial = ?", serial)
			if err != nil {
				m.log.AuditErrf("expiration-mailer: Error loading cert %q: %s", cert.Serial, err)
				return err
			}
			certs = append(certs, cert)
		}

		m.log.Infof("Found %d certificates expiring between %s and %s", len(certs),
			left.Format("2006-01-02 03:04"), right.Format("2006-01-02 03:04"))

		if len(certs) == 0 {
			continue // nothing to do
		}

		// If the `certs` result was exactly `m.limit` rows we need to increment
		// a stat indicating that this nag group is at capacity based on the
		// configured cert limit. If this condition continually occurs across mailer
		// runs then we will not catch up, resulting in under-sending expiration
		// mails. The effects of this were initially described in issue #2002[0].
		//
		// 0: https://github.com/letsencrypt/boulder/issues/2002
		if len(certs) == m.limit {
			m.log.Infof("nag group %s expiring certificates at configured capacity (cert limit %d)",
				expiresIn.String(), m.limit)
			m.stats.nagsAtCapacity.With(prometheus.Labels{"nagGroup": expiresIn.String()}).Set(1)
		}

		processingStarted := m.clk.Now()
		m.processCerts(certs)
		processingEnded := m.clk.Now()
		elapsed := processingEnded.Sub(processingStarted)
		m.stats.processingLatency.Observe(elapsed.Seconds())
	}

	return nil
}

type durationSlice []time.Duration

func (ds durationSlice) Len() int {
	return len(ds)
}

func (ds durationSlice) Less(a, b int) bool {
	return ds[a] < ds[b]
}

func (ds durationSlice) Swap(a, b int) {
	ds[a], ds[b] = ds[b], ds[a]
}

type config struct {
	Mailer struct {
		cmd.ServiceConfig
		cmd.DBConfig
		cmd.SMTPConfig

		From    string
		Subject string

		CertLimit int
		NagTimes  []string
		// How much earlier (than configured nag intervals) to
		// send reminders, to account for the expected delay
		// before the next expiration-mailer invocation.
		NagCheckInterval string
		// Path to a text/template email template
		EmailTemplate string

		Frequency cmd.ConfigDuration

		TLS       cmd.TLSConfig
		SAService *cmd.GRPCClientConfig

		// Path to a file containing a list of trusted root certificates for use
		// during the SMTP connection (as opposed to the gRPC connections).
		SMTPTrustedRootFile string

		Features map[string]bool
	}

	Syslog cmd.SyslogConfig
}

func initStats(scope metrics.Scope) mailerStats {
	nagsAtCapacity := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nagsAtCapacity",
			Help: "Count of nag groups at capcacity",
		},
		[]string{"nagGroup"})
	scope.MustRegister(nagsAtCapacity)

	errorCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "errors",
			Help: "Number of errors",
		},
		[]string{"type"})
	scope.MustRegister(errorCount)

	renewalCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "renewals",
			Help: "Number of messages skipped for being renewals",
		},
		nil)
	scope.MustRegister(renewalCount)

	sendLatency := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "sendLatency",
			Help:    "Time the mailer takes sending messages",
			Buckets: metrics.InternetFacingBuckets,
		})
	scope.MustRegister(sendLatency)

	processingLatency := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "processingLatency",
			Help: "Time the mailer takes processing certificates",
		})
	scope.MustRegister(processingLatency)

	return mailerStats{
		nagsAtCapacity:    nagsAtCapacity,
		errorCount:        errorCount,
		renewalCount:      renewalCount,
		sendLatency:       sendLatency,
		processingLatency: processingLatency,
	}
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	certLimit := flag.Int("cert_limit", 0, "Count of certificates to process per expiration period")
	reconnBase := flag.Duration("reconnectBase", 1*time.Second, "Base sleep duration between reconnect attempts")
	reconnMax := flag.Duration("reconnectMax", 5*60*time.Second, "Max sleep duration between reconnect attempts after exponential backoff")
	daemon := flag.Bool("daemon", false, "Run in daemon mode")

	flag.Parse()

	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")
	err = features.Set(c.Mailer.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.Mailer.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	if *certLimit > 0 {
		c.Mailer.CertLimit = *certLimit
	}
	// Default to 100 if no certLimit is set
	if c.Mailer.CertLimit == 0 {
		c.Mailer.CertLimit = 100
	}

	// Configure DB
	dbURL, err := c.Mailer.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, c.Mailer.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Could not connect to database")
	sa.SetSQLDebug(dbMap, logger)
	go sa.ReportDbConnCount(dbMap, scope)

	tlsConfig, err := c.Mailer.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clk := cmd.Clock()

	clientMetrics := bgrpc.NewClientMetrics(scope)
	conn, err := bgrpc.ClientSetup(c.Mailer.SAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := bgrpc.NewStorageAuthorityClient(sapb.NewStorageAuthorityClient(conn))

	var smtpRoots *x509.CertPool
	if c.Mailer.SMTPTrustedRootFile != "" {
		pem, err := ioutil.ReadFile(c.Mailer.SMTPTrustedRootFile)
		cmd.FailOnError(err, "Loading trusted roots file")
		smtpRoots = x509.NewCertPool()
		if !smtpRoots.AppendCertsFromPEM(pem) {
			cmd.FailOnError(nil, "Failed to parse root certs PEM")
		}
	}

	// Load email template
	emailTmpl, err := ioutil.ReadFile(c.Mailer.EmailTemplate)
	cmd.FailOnError(err, fmt.Sprintf("Could not read email template file [%s]", c.Mailer.EmailTemplate))
	tmpl, err := template.New("expiry-email").Parse(string(emailTmpl))
	cmd.FailOnError(err, "Could not parse email template")

	// If there is no configured subject template, use a default
	if c.Mailer.Subject == "" {
		c.Mailer.Subject = defaultExpirationSubject
	}
	// Load subject template
	subjTmpl, err := template.New("expiry-email-subject").Parse(c.Mailer.Subject)
	cmd.FailOnError(err, fmt.Sprintf("Could not parse email subject template"))

	fromAddress, err := netmail.ParseAddress(c.Mailer.From)
	cmd.FailOnError(err, fmt.Sprintf("Could not parse from address: %s", c.Mailer.From))

	smtpPassword, err := c.Mailer.PasswordConfig.Pass()
	cmd.FailOnError(err, "Failed to load SMTP password")
	mailClient := bmail.New(
		c.Mailer.Server,
		c.Mailer.Port,
		c.Mailer.Username,
		smtpPassword,
		smtpRoots,
		*fromAddress,
		logger,
		scope,
		*reconnBase,
		*reconnMax)

	nagCheckInterval := defaultNagCheckInterval
	if s := c.Mailer.NagCheckInterval; s != "" {
		nagCheckInterval, err = time.ParseDuration(s)
		if err != nil {
			logger.AuditErrf("Failed to parse NagCheckInterval string %q: %s", s, err)
			return
		}
	}

	var nags durationSlice
	for _, nagDuration := range c.Mailer.NagTimes {
		dur, err := time.ParseDuration(nagDuration)
		if err != nil {
			logger.AuditErrf("Failed to parse nag duration string [%s]: %s", nagDuration, err)
			return
		}
		nags = append(nags, dur+nagCheckInterval)
	}
	// Make sure durations are sorted in increasing order
	sort.Sort(nags)

	m := mailer{
		log:             logger,
		dbMap:           dbMap,
		rs:              sac,
		mailer:          mailClient,
		subjectTemplate: subjTmpl,
		emailTemplate:   tmpl,
		nagTimes:        nags,
		limit:           c.Mailer.CertLimit,
		clk:             clk,
		stats:           initStats(scope),
	}

	// Prefill this labelled stat with the possible label values, so each value is
	// set to 0 on startup, rather than being missing from stats collection until
	// the first mail run.
	for _, expiresIn := range nags {
		m.stats.nagsAtCapacity.With(prometheus.Labels{"nagGroup": expiresIn.String()}).Set(0)
	}

	if *daemon {
		if c.Mailer.Frequency.Duration == 0 {
			fmt.Fprintln(os.Stderr, "mailer.runPeriod is not set")
			os.Exit(1)
		}
		t := time.NewTicker(c.Mailer.Frequency.Duration)
		for range t.C {
			err = m.findExpiringCertificates()
			cmd.FailOnError(err, "expiration-mailer has failed")
		}
	} else {
		err = m.findExpiringCertificates()
		cmd.FailOnError(err, "expiration-mailer has failed")
	}
}
