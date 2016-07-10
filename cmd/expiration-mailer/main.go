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
	"os"
	"sort"
	"strings"
	"text/template"
	"time"

	"golang.org/x/net/context"

	"github.com/cactus/go-statsd-client/statsd"
	"github.com/jmhodges/clock"
	"gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mail"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

const defaultNagCheckInterval = 24 * time.Hour

type emailContent struct {
	ExpirationDate   string
	DaysToExpiration int
	DNSNames         string
}

type regStore interface {
	GetRegistration(context.Context, int64) (core.Registration, error)
}

type mailer struct {
	stats         statsd.Statter
	log           blog.Logger
	dbMap         *gorp.DbMap
	rs            regStore
	mailer        mail.Mailer
	emailTemplate *template.Template
	subject       string
	nagTimes      []time.Duration
	limit         int
	clk           clock.Clock
}

func (m *mailer) sendNags(contacts []*core.AcmeURL, certs []*x509.Certificate) error {
	if len(contacts) == 0 {
		return nil
	}
	if len(certs) == 0 {
		return errors.New("no certs given to send nags for")
	}
	emails := []string{}
	for _, contact := range contacts {
		if contact.Scheme == "mailto" {
			emails = append(emails, contact.Opaque)
		}
	}
	if len(emails) == 0 {
		return nil
	}

	expiresIn := time.Duration(math.MaxInt64)
	expDate := m.clk.Now()
	domains := []string{}

	// Pick out the expiration date that is closest to being hit.
	for _, cert := range certs {
		domains = append(domains, cert.DNSNames...)
		possible := cert.NotAfter.Sub(m.clk.Now())
		if possible < expiresIn {
			expiresIn = possible
			expDate = cert.NotAfter
		}
	}
	domains = core.UniqueLowerNames(domains)
	sort.Strings(domains)

	email := emailContent{
		ExpirationDate:   expDate.UTC().Format(time.RFC822Z),
		DaysToExpiration: int(expiresIn.Hours() / 24),
		DNSNames:         strings.Join(domains, "\n"),
	}
	msgBuf := new(bytes.Buffer)
	err := m.emailTemplate.Execute(msgBuf, email)
	if err != nil {
		m.stats.Inc("Mailer.Expiration.Errors.SendingNag.TemplateFailure", 1, 1.0)
		return err
	}
	startSending := m.clk.Now()
	err = m.mailer.SendMail(emails, m.subject, msgBuf.String())
	if err != nil {
		m.stats.Inc("Mailer.Expiration.Errors.SendingNag.SendFailure", 1, 1.0)
		return err
	}
	m.stats.TimingDuration("Mailer.Expiration.SendLatency", time.Since(startSending), 1.0)
	m.stats.Inc("Mailer.Expiration.Sent", int64(len(emails)), 1.0)
	return nil
}

func (m *mailer) updateCertStatus(serial string) error {
	// Update CertificateStatus object
	tx, err := m.dbMap.Begin()
	if err != nil {
		err = sa.Rollback(tx, err)
		m.log.AuditErr(fmt.Sprintf("Error opening transaction for certificate %s: %s", serial, err))
		return err
	}

	csObj, err := tx.Get(&core.CertificateStatus{}, serial)
	if err != nil {
		err = sa.Rollback(tx, err)
		m.log.AuditErr(fmt.Sprintf("Error fetching status for certificate %s: %s", serial, err))
		return err
	}
	certStatus := csObj.(*core.CertificateStatus)
	certStatus.LastExpirationNagSent = m.clk.Now()

	_, err = tx.Update(certStatus)
	if err != nil {
		err = sa.Rollback(tx, err)
		m.log.AuditErr(fmt.Sprintf("Error updating status for certificate %s: %s", serial, err))
		return err
	}

	err = tx.Commit()
	if err != nil {
		err = sa.Rollback(tx, err)
		m.log.AuditErr(fmt.Sprintf("Error committing transaction for certificate %s: %s", serial, err))
		return err
	}

	return nil
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
	return present == 1, err
}

func (m *mailer) processCerts(allCerts []core.Certificate) {
	ctx := context.Background()
	m.log.Info(fmt.Sprintf("expiration-mailer: Found %d certificates, starting sending messages", len(allCerts)))

	regIDToCerts := make(map[int64][]core.Certificate)

	for _, cert := range allCerts {
		cs := regIDToCerts[cert.RegistrationID]
		cs = append(cs, cert)
		regIDToCerts[cert.RegistrationID] = cs
	}

	for regID, certs := range regIDToCerts {
		reg, err := m.rs.GetRegistration(ctx, regID)
		if err != nil {
			m.log.AuditErr(fmt.Sprintf("Error fetching registration %d: %s", regID, err))
			m.stats.Inc("Mailer.Expiration.Errors.GetRegistration", 1, 1.0)
			continue
		}

		parsedCerts := []*x509.Certificate{}
		for _, cert := range certs {
			parsedCert, err := x509.ParseCertificate(cert.DER)
			if err != nil {
				// TODO(#1420): tell registration about this error
				m.log.AuditErr(fmt.Sprintf("Error parsing certificate %s: %s", cert.Serial, err))
				m.stats.Inc("Mailer.Expiration.Errors.ParseCertificate", 1, 1.0)
				continue
			}

			renewed, err := m.certIsRenewed(cert.Serial)
			if err != nil {
				m.log.AuditErr(fmt.Sprintf("expiration-mailer: error fetching renewal state: %v", err))
				// assume not renewed
			} else if renewed {
				m.stats.Inc("Mailer.Expiration.Renewed", 1, 1.0)
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
			m.log.AuditErr(fmt.Sprintf("Error sending nag emails: %s", err))
			continue
		}
		for _, cert := range parsedCerts {
			serial := core.SerialToString(cert.SerialNumber)
			err = m.updateCertStatus(serial)
			if err != nil {
				m.log.AuditErr(fmt.Sprintf("Error updating certificate status for %s: %s", serial, err))
				m.stats.Inc("Mailer.Expiration.Errors.UpdateCertificateStatus", 1, 1.0)
				continue
			}
		}
	}
	m.log.Info("expiration-mailer: Finished sending messages")
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

		m.log.Info(fmt.Sprintf("expiration-mailer: Searching for certificates that expire between %s and %s and had last nag >%s before expiry",
			left.UTC(), right.UTC(), expiresIn))
		var certs []core.Certificate
		_, err := m.dbMap.Select(
			&certs,
			`SELECT cert.* FROM certificates AS cert
			 JOIN certificateStatus AS cs
			 ON cs.serial = cert.serial
			 AND cert.expires > :cutoffA
			 AND cert.expires <= :cutoffB
			 AND cs.status != "revoked"
			 AND COALESCE(TIMESTAMPDIFF(SECOND, cs.lastExpirationNagSent, cert.expires) > :nagCutoff, 1)
			 ORDER BY cert.expires ASC
			 LIMIT :limit`,
			map[string]interface{}{
				"cutoffA":   left,
				"cutoffB":   right,
				"nagCutoff": expiresIn.Seconds(),
				"limit":     m.limit,
			},
		)
		if err != nil {
			m.log.AuditErr(fmt.Sprintf("expiration-mailer: Error loading certificates: %s", err))
			return err // fatal
		}

		if len(certs) == 0 {
			continue // nothing to do
		}

		processingStarted := m.clk.Now()
		m.processCerts(certs)
		m.stats.TimingDuration("Mailer.Expiration.ProcessingCertificatesLatency", time.Since(processingStarted), 1.0)
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

const clientName = "ExpirationMailer"

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
	}

	Statsd cmd.StatsdConfig

	Syslog cmd.SyslogConfig
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	certLimit := flag.Int("cert_limit", 0, "Count of certificates to process per expiration period")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadJSONFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	go cmd.DebugServer(c.Mailer.DebugAddr)

	stats, logger := cmd.StatsAndLogging(c.Statsd, c.Syslog)
	defer logger.AuditPanic()
	logger.Info(clientName)

	// Prefer the command line flag cert_limit
	if *certLimit > 0 {
		c.Mailer.CertLimit = *certLimit
	}

	// Configure DB
	dbURL, err := c.Mailer.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, c.Mailer.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Could not connect to database")
	go sa.ReportDbConnCount(dbMap, metrics.NewStatsdScope(stats, "ExpirationMailer"))

	amqpConf := c.Mailer.AMQP
	sac, err := rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
	cmd.FailOnError(err, "Failed to create SA client")

	// Load email template
	emailTmpl, err := ioutil.ReadFile(c.Mailer.EmailTemplate)
	cmd.FailOnError(err, fmt.Sprintf("Could not read email template file [%s]", c.Mailer.EmailTemplate))
	tmpl, err := template.New("expiry-email").Parse(string(emailTmpl))
	cmd.FailOnError(err, "Could not parse email template")

	fromAddress, err := netmail.ParseAddress(c.Mailer.From)
	cmd.FailOnError(err, fmt.Sprintf("Could not parse from address: %s", c.Mailer.From))

	smtpPassword, err := c.Mailer.PasswordConfig.Pass()
	cmd.FailOnError(err, "Failed to load SMTP password")
	mailClient := mail.New(c.Mailer.Server, c.Mailer.Port, c.Mailer.Username, smtpPassword, *fromAddress)
	err = mailClient.Connect()
	cmd.FailOnError(err, "Couldn't connect to mail server.")
	defer func() {
		_ = mailClient.Close()
	}()

	nagCheckInterval := defaultNagCheckInterval
	if s := c.Mailer.NagCheckInterval; s != "" {
		nagCheckInterval, err = time.ParseDuration(s)
		if err != nil {
			logger.AuditErr(fmt.Sprintf("Failed to parse NagCheckInterval string %q: %s", s, err))
			return
		}
	}

	var nags durationSlice
	for _, nagDuration := range c.Mailer.NagTimes {
		dur, err := time.ParseDuration(nagDuration)
		if err != nil {
			logger.AuditErr(fmt.Sprintf("Failed to parse nag duration string [%s]: %s", nagDuration, err))
			return
		}
		nags = append(nags, dur+nagCheckInterval)
	}
	// Make sure durations are sorted in increasing order
	sort.Sort(nags)

	subject := "Certificate expiration notice"
	if c.Mailer.Subject != "" {
		subject = c.Mailer.Subject
	}
	m := mailer{
		stats:         stats,
		subject:       subject,
		log:           logger,
		dbMap:         dbMap,
		rs:            sac,
		mailer:        mailClient,
		emailTemplate: tmpl,
		nagTimes:      nags,
		limit:         c.Mailer.CertLimit,
		clk:           cmd.Clock(),
	}

	err = m.findExpiringCertificates()
	cmd.FailOnError(err, "expiration-mailer has failed")
}
