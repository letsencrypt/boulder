// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/mail"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

const defaultNagCheckInterval = 24 * time.Hour

type emailContent struct {
	ExpirationDate   time.Time
	DaysToExpiration int
	DNSNames         string
}

type regStore interface {
	GetRegistration(int64) (core.Registration, error)
}

type mailer struct {
	stats         statsd.Statter
	log           *blog.AuditLogger
	dbMap         *gorp.DbMap
	rs            regStore
	mailer        mail.Mailer
	emailTemplate *template.Template
	nagTimes      []time.Duration
	limit         int
	clk           clock.Clock
}

func (m *mailer) sendNags(parsedCert *x509.Certificate, contacts []*core.AcmeURL) error {
	expiresIn := int(parsedCert.NotAfter.Sub(m.clk.Now()).Hours() / 24)
	emails := []string{}
	for _, contact := range contacts {
		if contact.Scheme == "mailto" {
			emails = append(emails, contact.Opaque)
		}
	}
	if len(emails) > 0 {
		email := emailContent{
			ExpirationDate:   parsedCert.NotAfter,
			DaysToExpiration: expiresIn,
			DNSNames:         strings.Join(parsedCert.DNSNames, ", "),
		}
		msgBuf := new(bytes.Buffer)
		err := m.emailTemplate.Execute(msgBuf, email)
		if err != nil {
			m.stats.Inc("Mailer.Expiration.Errors.SendingNag.TemplateFailure", 1, 1.0)
			return err
		}
		startSending := m.clk.Now()
		err = m.mailer.SendMail(emails, msgBuf.String())
		if err != nil {
			m.stats.Inc("Mailer.Expiration.Errors.SendingNag.SendFailure", 1, 1.0)
			return err
		}
		m.stats.TimingDuration("Mailer.Expiration.SendLatency", time.Since(startSending), 1.0)
		m.stats.Inc("Mailer.Expiration.Sent", int64(len(emails)), 1.0)
	}
	return nil
}

func (m *mailer) updateCertStatus(serial string) error {
	// Update CertificateStatus object
	tx, err := m.dbMap.Begin()
	if err != nil {
		m.log.Err(fmt.Sprintf("Error opening transaction for certificate %s: %s", serial, err))
		tx.Rollback()
		return err
	}

	csObj, err := tx.Get(&core.CertificateStatus{}, serial)
	if err != nil {
		m.log.Err(fmt.Sprintf("Error fetching status for certificate %s: %s", serial, err))
		tx.Rollback()
		return err
	}
	certStatus := csObj.(*core.CertificateStatus)
	certStatus.LastExpirationNagSent = m.clk.Now()

	_, err = tx.Update(certStatus)
	if err != nil {
		m.log.Err(fmt.Sprintf("Error updating status for certificate %s: %s", serial, err))
		tx.Rollback()
		return err
	}

	err = tx.Commit()
	if err != nil {
		m.log.Err(fmt.Sprintf("Error committing transaction for certificate %s: %s", serial, err))
		tx.Rollback()
		return err
	}

	return nil
}

func (m *mailer) processCerts(certs []core.Certificate) {
	m.log.Info(fmt.Sprintf("expiration-mailer: Found %d certificates, starting sending messages", len(certs)))

	for _, cert := range certs {
		reg, err := m.rs.GetRegistration(cert.RegistrationID)
		if err != nil {
			m.log.Err(fmt.Sprintf("Error fetching registration %d: %s", cert.RegistrationID, err))
			m.stats.Inc("Mailer.Expiration.Errors.GetRegistration", 1, 1.0)
			continue
		}
		parsedCert, err := x509.ParseCertificate(cert.DER)
		if err != nil {
			m.log.Err(fmt.Sprintf("Error parsing certificate %s: %s", cert.Serial, err))
			m.stats.Inc("Mailer.Expiration.Errors.ParseCertificate", 1, 1.0)
			continue
		}
		err = m.sendNags(parsedCert, reg.Contact)
		if err != nil {
			m.log.Err(fmt.Sprintf("Error sending nag emails: %s", err))
			continue
		}
		err = m.updateCertStatus(cert.Serial)
		if err != nil {
			m.log.Err(fmt.Sprintf("Error updating certificate status for %s: %s", cert.Serial, err))
			m.stats.Inc("Mailer.Expiration.Errors.UpdateCertificateStatus", 1, 1.0)
			continue
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

		m.log.Info(fmt.Sprintf("expiration-mailer: Searching for certificates that expire between %s and %s and had last nag >%s before expiry", left, right, expiresIn))
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
			m.log.Err(fmt.Sprintf("expiration-mailer: Error loading certificates: %s", err))
			return err // fatal
		}
		if len(certs) > 0 {
			processingStarted := m.clk.Now()
			m.processCerts(certs)
			m.stats.TimingDuration("Mailer.Expiration.ProcessingCertificatesLatency", time.Since(processingStarted), 1.0)
		}
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

func main() {
	app := cmd.NewAppShell("expiration-mailer", "Sends certificate expiration emails")

	app.App.Flags = append(app.App.Flags, cli.IntFlag{
		Name:   "cert_limit",
		Value:  100,
		EnvVar: "CERT_LIMIT",
		Usage:  "Count of certificates to process per expiration period",
	})

	app.Config = func(c *cli.Context, config cmd.Config) cmd.Config {
		if c.GlobalInt("cert_limit") > 0 {
			config.Mailer.CertLimit = c.GlobalInt("cert_limit")
		}
		return config
	}

	app.Action = func(c cmd.Config, stats statsd.Statter, auditlogger *blog.AuditLogger) {
		go cmd.DebugServer(c.Mailer.DebugAddr)

		// Configure DB
		dbURL, err := c.Mailer.DBConfig.URL()
		cmd.FailOnError(err, "Couldn't load DB URL")
		dbMap, err := sa.NewDbMap(dbURL)
		cmd.FailOnError(err, "Could not connect to database")

		amqpConf := c.Mailer.AMQP
		sac, err := rpc.NewStorageAuthorityClient(clientName, amqpConf, stats)
		cmd.FailOnError(err, "Failed to create SA client")

		// Load email template
		emailTmpl, err := ioutil.ReadFile(c.Mailer.EmailTemplate)
		cmd.FailOnError(err, fmt.Sprintf("Could not read email template file [%s]", c.Mailer.EmailTemplate))
		tmpl, err := template.New("expiry-email").Parse(string(emailTmpl))
		cmd.FailOnError(err, "Could not parse email template")

		mailClient := mail.New(c.Mailer.Server, c.Mailer.Port, c.Mailer.Username, c.Mailer.Password)

		nagCheckInterval := defaultNagCheckInterval
		if s := c.Mailer.NagCheckInterval; s != "" {
			nagCheckInterval, err = time.ParseDuration(s)
			if err != nil {
				auditlogger.Err(fmt.Sprintf("Failed to parse NagCheckInterval string %q: %s", s, err))
				return
			}
		}

		var nags durationSlice
		for _, nagDuration := range c.Mailer.NagTimes {
			dur, err := time.ParseDuration(nagDuration)
			if err != nil {
				auditlogger.Err(fmt.Sprintf("Failed to parse nag duration string [%s]: %s", nagDuration, err))
				return
			}
			nags = append(nags, dur+nagCheckInterval)
		}
		// Make sure durations are sorted in increasing order
		sort.Sort(nags)

		m := mailer{
			stats:         stats,
			log:           auditlogger,
			dbMap:         dbMap,
			rs:            sac,
			mailer:        &mailClient,
			emailTemplate: tmpl,
			nagTimes:      nags,
			limit:         c.Mailer.CertLimit,
			clk:           clock.Default(),
		}

		auditlogger.Info("expiration-mailer: Starting")
		err = m.findExpiringCertificates()
		cmd.FailOnError(err, "expiration-mailer has failed")
	}

	app.Run()
}
