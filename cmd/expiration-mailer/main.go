package notmain

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
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
	"sync"
	"text/template"
	"time"

	"github.com/honeycombio/beeline-go"
	"github.com/jmhodges/clock"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/db"
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
	GetRegistration(ctx context.Context, req *sapb.RegistrationID, _ ...grpc.CallOption) (*corepb.Registration, error)
}

type mailer struct {
	log             blog.Logger
	dbMap           *db.WrappedMap
	rs              regStore
	mailer          bmail.Mailer
	emailTemplate   *template.Template
	subjectTemplate *template.Template
	nagTimes        []time.Duration
	parallelSends   uint
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

func (m *mailer) sendNags(conn bmail.Conn, contacts []string, certs []*x509.Certificate) error {
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

	logItem := struct {
		Rcpt             []string
		Serials          []string
		DaysToExpiration int
		DNSNames         []string
	}{
		Rcpt:             emails,
		Serials:          serials,
		DaysToExpiration: email.DaysToExpiration,
		DNSNames:         domains,
	}
	logStr, err := json.Marshal(logItem)
	if err != nil {
		m.log.Errf("logItem could not be serialized to JSON. Raw: %+v", logItem)
		return err
	}
	m.log.Infof("attempting send JSON=%s", string(logStr))

	startSending := m.clk.Now()
	err = conn.SendMail(emails, subjBuf.String(), msgBuf.String())
	if err != nil {
		m.log.Errf("failed send JSON=%s", string(logStr))
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

func (m *mailer) certIsRenewed(names []string, issued time.Time) (bool, error) {
	namehash := sa.HashNames(names)

	var present bool
	err := m.dbMap.SelectOne(
		&present,
		`SELECT EXISTS (SELECT id FROM fqdnSets WHERE setHash = ? AND issued > ? LIMIT 1)`,
		namehash,
		issued,
	)
	return present, err
}

type work struct {
	regID int64
	certs []core.Certificate
}

func (m *mailer) processCerts(ctx context.Context, allCerts []core.Certificate) {
	regIDToCerts := make(map[int64][]core.Certificate)

	for _, cert := range allCerts {
		cs := regIDToCerts[cert.RegistrationID]
		cs = append(cs, cert)
		regIDToCerts[cert.RegistrationID] = cs
	}

	var wg sync.WaitGroup
	workChan := make(chan work)

	parallelSends := m.parallelSends
	if parallelSends == 0 {
		parallelSends = 1
	}

	for senderNum := uint(0); senderNum < parallelSends; senderNum++ {
		conn, err := m.mailer.Connect()
		if err != nil {
			m.log.AuditErrf("connecting parallel sender %d: %s", senderNum, err)
			close(workChan)
			return
		}

		wg.Add(1)
		go func(conn bmail.Conn, ch <-chan work) {
			defer wg.Done()
			for w := range ch {
				err := m.sendToOneRegID(ctx, conn, w.regID, w.certs)
				if err != nil {
					m.log.AuditErr(err.Error())
				}
			}
			conn.Close()
		}(conn, workChan)

		// For politeness' sake, don't open more than 1 new connection per
		// second.
		time.Sleep(time.Second)
	}
	for regID, certs := range regIDToCerts {
		workChan <- work{regID, certs}
	}
	close(workChan)
	wg.Wait()
}

func (m *mailer) sendToOneRegID(ctx context.Context, conn bmail.Conn, regID int64, certs []core.Certificate) error {
	reg, err := m.rs.GetRegistration(ctx, &sapb.RegistrationID{Id: regID})
	if err != nil {
		m.stats.errorCount.With(prometheus.Labels{"type": "GetRegistration"}).Inc()
		return fmt.Errorf("fetching registration %d: %w", regID, err)
	}

	if reg.Contact == nil {
		return nil
	}

	parsedCerts := []*x509.Certificate{}
	for _, cert := range certs {
		parsedCert, err := x509.ParseCertificate(cert.DER)
		if err != nil {
			m.stats.errorCount.With(prometheus.Labels{"type": "ParseCertificate"}).Inc()
			// TODO(#1420): tell registration about this error
			return fmt.Errorf("parsing certificate %s: %w", cert.Serial, err)
		}

		renewed, err := m.certIsRenewed(parsedCert.DNSNames, parsedCert.NotBefore)
		if err != nil {
			return fmt.Errorf("expiration-mailer: error fetching renewal state: %w", err)
		} else if renewed {
			m.stats.renewalCount.With(prometheus.Labels{}).Inc()
			err := m.updateCertStatus(cert.Serial)
			if err != nil {
				m.stats.errorCount.With(prometheus.Labels{"type": "UpdateCertificateStatus"}).Inc()
				return fmt.Errorf("updating certificate status for %s: %w", cert.Serial, err)
			}
			continue
		}

		parsedCerts = append(parsedCerts, parsedCert)
	}

	if len(parsedCerts) == 0 {
		// all certificates are renewed
		return nil
	}

	err = m.sendNags(conn, reg.Contact, parsedCerts)
	if err != nil {
		m.stats.errorCount.With(prometheus.Labels{"type": "SendNags"}).Inc()
		return fmt.Errorf("sending nag emails: %w", err)
	}
	for _, cert := range parsedCerts {
		serial := core.SerialToString(cert.SerialNumber)
		err = m.updateCertStatus(serial)
		if err != nil {
			// Don't return immediately; we'd like to at least try and update the status for
			// all certificates, even if one of them experienced an error (which might have
			// been intermittent)
			m.log.AuditErrf("updating certificate status for %s: %s", serial, err)
			m.stats.errorCount.With(prometheus.Labels{"type": "UpdateCertificateStatus"}).Inc()
			continue
		}
	}
	return nil
}

func (m *mailer) findExpiringCertificates(ctx context.Context) error {
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
		_, err := m.dbMap.WithContext(ctx).Select(
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

		// If the number of rows was exactly `m.limit` rows we need to increment
		// a stat indicating that this nag group is at capacity based on the
		// configured cert limit. If this condition continually occurs across mailer
		// runs then we will not catch up, resulting in under-sending expiration
		// mails. The effects of this were initially described in issue #2002[0].
		//
		// 0: https://github.com/letsencrypt/boulder/issues/2002
		atCapacity := float64(0)
		if len(serials) == m.limit {
			m.log.Infof("nag group %s expiring certificates at configured capacity (select limit %d)",
				expiresIn.String(), m.limit)
			atCapacity = float64(1)
		}
		m.stats.nagsAtCapacity.With(prometheus.Labels{"nag_group": expiresIn.String()}).Set(atCapacity)

		// Now we can sequentially retrieve the certificate details for each of the
		// certificate status rows
		var certs []core.Certificate
		for _, serial := range serials {
			var cert core.Certificate
			cert, err := sa.SelectCertificate(m.dbMap.WithContext(ctx), serial)
			if err != nil {
				// We can get a NoRowsErr when processing a serial number corresponding
				// to a precertificate with no final certificate. Since this certificate
				// is not being used by a subscriber, we don't send expiration email about
				// it.
				if db.IsNoRows(err) {
					continue
				}
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

		processingStarted := m.clk.Now()
		m.processCerts(ctx, certs)
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

type Config struct {
	Mailer struct {
		cmd.ServiceConfig
		DB cmd.DBConfig
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

		// How often to process a batch of certificates
		Frequency cmd.ConfigDuration

		// How many parallel goroutines should process each batch of emails
		ParallelSends uint

		TLS       cmd.TLSConfig
		SAService *cmd.GRPCClientConfig

		// Path to a file containing a list of trusted root certificates for use
		// during the SMTP connection (as opposed to the gRPC connections).
		SMTPTrustedRootFile string

		Features map[string]bool
	}

	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig
}

func initStats(stats prometheus.Registerer) mailerStats {
	nagsAtCapacity := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "nags_at_capacity",
			Help: "Count of nag groups at capcacity",
		},
		[]string{"nag_group"})
	stats.MustRegister(nagsAtCapacity)

	errorCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "errors",
			Help: "Number of errors",
		},
		[]string{"type"})
	stats.MustRegister(errorCount)

	renewalCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "renewals",
			Help: "Number of messages skipped for being renewals",
		},
		nil)
	stats.MustRegister(renewalCount)

	sendLatency := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "send_latency",
			Help:    "Time the mailer takes sending messages in seconds",
			Buckets: metrics.InternetFacingBuckets,
		})
	stats.MustRegister(sendLatency)

	processingLatency := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "processing_latency",
			Help:    "Time the mailer takes processing certificates in seconds",
			Buckets: []float64{1, 15, 30, 60, 75, 90, 120},
		})
	stats.MustRegister(processingLatency)

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

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")
	err = features.Set(c.Mailer.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	bc, err := c.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

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

	dbMap, err := sa.InitWrappedDb(c.Mailer.DB, scope, logger)
	cmd.FailOnError(err, "While initializing dbMap")

	tlsConfig, err := c.Mailer.TLS.Load()
	cmd.FailOnError(err, "TLS config")

	clk := cmd.Clock()

	clientMetrics := bgrpc.NewClientMetrics(scope)
	conn, err := bgrpc.ClientSetup(c.Mailer.SAService, tlsConfig, clientMetrics, clk)
	cmd.FailOnError(err, "Failed to load credentials and create gRPC connection to SA")
	sac := sapb.NewStorageAuthorityClient(conn)

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
	cmd.FailOnError(err, "Could not parse email subject template")

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
		parallelSends:   c.Mailer.ParallelSends,
		clk:             clk,
		stats:           initStats(scope),
	}

	// Prefill this labelled stat with the possible label values, so each value is
	// set to 0 on startup, rather than being missing from stats collection until
	// the first mail run.
	for _, expiresIn := range nags {
		m.stats.nagsAtCapacity.With(prometheus.Labels{"nag_group": expiresIn.String()}).Set(0)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go cmd.CatchSignals(logger, func() {
		fmt.Printf("exiting\n")
		cancel()
		select {} // wait for the `findExpiringCertificates` calls below to exit
	})

	if *daemon {
		if c.Mailer.Frequency.Duration == 0 {
			fmt.Fprintln(os.Stderr, "mailer.runPeriod is not set")
			os.Exit(1)
		}
		t := time.NewTicker(c.Mailer.Frequency.Duration)
		for {
			select {
			case <-t.C:
				err = m.findExpiringCertificates(ctx)
				cmd.FailOnError(err, "expiration-mailer has failed")
			case <-ctx.Done():
				os.Exit(0)
			}
		}
	} else {
		err = m.findExpiringCertificates(ctx)
		cmd.FailOnError(err, "expiration-mailer has failed")
	}
}

func init() {
	cmd.RegisterCommand("expiration-mailer", main)
}
