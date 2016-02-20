// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/sa"
)

const (
	good = "valid"
	bad  = "invalid"

	filenameLayout = "20060102"

	checkPeriod = time.Hour * 24 * 90

	batchSize = 1000
)

type report struct {
	begin     time.Time
	end       time.Time
	GoodCerts int64
	BadCerts  int64
	Entries   map[string]reportEntry
}

func (r *report) save(directory string) error {
	filename := path.Join(directory, fmt.Sprintf(
		"%s-%s-report.json",
		r.begin.Format(filenameLayout),
		r.end.Format(filenameLayout),
	))
	content, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, content, os.ModePerm)
}

type reportEntry struct {
	Valid    bool     `json:"valid"`
	Problems []string `json:"problem,omitempty"`
}

type certChecker struct {
	pa           core.PolicyAuthority
	dbMap        *gorp.DbMap
	certs        chan core.Certificate
	clock        clock.Clock
	rMu          *sync.Mutex
	issuedReport report
}

func newChecker(saDbMap *gorp.DbMap, paDbMap *gorp.DbMap, clk clock.Clock, enforceWhitelist bool, challengeTypes map[string]bool) certChecker {
	pa, err := policy.New(paDbMap, enforceWhitelist, challengeTypes)
	cmd.FailOnError(err, "Failed to create PA")
	c := certChecker{
		pa:    pa,
		dbMap: saDbMap,
		certs: make(chan core.Certificate, batchSize),
		rMu:   new(sync.Mutex),
		clock: clk,
	}
	c.issuedReport.Entries = make(map[string]reportEntry)

	return c
}

func (c *certChecker) getCerts() error {
	c.issuedReport.end = c.clock.Now()
	c.issuedReport.begin = c.issuedReport.end.Add(-checkPeriod)

	var count int
	err := c.dbMap.SelectOne(
		&count,
		"SELECT count(*) FROM certificates WHERE issued >= :issued",
		map[string]interface{}{"issued": c.issuedReport.begin},
	)
	if err != nil {
		return err
	}

	// Retrieve certs in batches of 1000 (the size of the certificate channel)
	// so that we don't eat unnecessary amounts of memory and avoid the 16MB MySQL
	// packet limit.
	// TODO(#701): This query needs to make better use of indexes
	for offset := 0; offset < count; {
		var certs []core.Certificate
		_, err = c.dbMap.Select(
			&certs,
			"SELECT * FROM certificates WHERE issued >= :issued ORDER BY issued ASC LIMIT :limit OFFSET :offset",
			map[string]interface{}{"issued": c.issuedReport.begin, "limit": batchSize, "offset": offset},
		)
		if err != nil {
			return err
		}
		for _, cert := range certs {
			c.certs <- cert
		}
		offset += len(certs)
	}

	// Close channel so range operations won't block once the channel empties out
	close(c.certs)
	return nil
}

func (c *certChecker) processCerts(wg *sync.WaitGroup) {
	for cert := range c.certs {
		problems := c.checkCert(cert)
		valid := len(problems) == 0
		c.rMu.Lock()
		c.issuedReport.Entries[cert.Serial] = reportEntry{
			Valid:    valid,
			Problems: problems,
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
		if validityPeriod > checkPeriod {
			problems = append(problems, fmt.Sprintf("Certificate has a validity period longer than %s", checkPeriod))
		} else if validityPeriod < checkPeriod {
			problems = append(problems, fmt.Sprintf("Certificate has a validity period shorter than %s", checkPeriod))
		}

		if parsedCert.NotBefore.Before(cert.Issued.Add(-6*time.Hour)) || parsedCert.NotBefore.After(cert.Issued.Add(6*time.Hour)) {
			problems = append(problems, "Stored issuance date is outside of 6 hour window of certificate NotBefore")
		}

		// Check that the PA is still willing to issue for each name in DNSNames + CommonName
		for _, name := range append(parsedCert.DNSNames, parsedCert.Subject.CommonName) {
			id := core.AcmeIdentifier{Type: core.IdentifierDNS, Value: name}
			if err = c.pa.WillingToIssue(id, cert.RegistrationID); err != nil {
				problems = append(problems, fmt.Sprintf("Policy Authority isn't willing to issue for %s: %s", name, err))
			}
		}
		// Check the cert has the correct key usage extensions
		if !reflect.DeepEqual(parsedCert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
			problems = append(problems, "Certificate has incorrect key usage extensions")
		}
	}
	return problems
}

func main() {
	app := cmd.NewAppShell("cert-checker", "Checks validity of certificates issued in the last 90 days")
	app.App.Flags = append(app.App.Flags, cli.IntFlag{
		Name:  "workers",
		Value: runtime.NumCPU(),
		Usage: "The number of concurrent workers used to process certificates",
	}, cli.StringFlag{
		Name:  "report-dir-path",
		Usage: "The path to write a JSON report on the certificates checks to (if no path is provided the report will not be written out)",
	}, cli.StringFlag{
		Name:  "db-connect",
		Usage: "SQL URI if not provided in the configuration file",
	})

	app.Config = func(c *cli.Context, config cmd.Config) cmd.Config {
		config.CertChecker.ReportDirectoryPath = c.GlobalString("report-dir-path")

		if connect := c.GlobalString("db-connect"); connect != "" {
			config.CertChecker.DBConnect = connect
		}

		if workers := c.GlobalInt("workers"); workers != 0 {
			config.CertChecker.Workers = workers
		}

		return config
	}

	app.Action = func(c cmd.Config, stats statsd.Statter, auditlogger *blog.AuditLogger) {
		// Validate PA config and set defaults if needed
		cmd.FailOnError(c.PA.CheckChallenges(), "Invalid PA configuration")

		saDbURL, err := c.CertChecker.DBConfig.URL()
		cmd.FailOnError(err, "Couldn't load DB URL")
		saDbMap, err := sa.NewDbMap(saDbURL)
		cmd.FailOnError(err, "Could not connect to database")

		paDbURL, err := c.PA.DBConfig.URL()
		cmd.FailOnError(err, "Couldn't load DB URL")
		paDbMap, err := sa.NewDbMap(paDbURL)
		cmd.FailOnError(err, "Could not connect to policy database")

		checker := newChecker(saDbMap, paDbMap, clock.Default(), c.PA.EnforcePolicyWhitelist, c.PA.Challenges)
		auditlogger.Info("# Getting certificates issued in the last 90 days")

		// Since we grab certificates in batches we don't want this to block, when it
		// is finished it will close the certificate channel which allows the range
		// loops in checker.processCerts to break
		go func() {
			err = checker.getCerts()
			cmd.FailOnError(err, "Batch retrieval of certificates failed")
		}()

		auditlogger.Info(fmt.Sprintf("# Processing certificates using %d workers", c.CertChecker.Workers))
		wg := new(sync.WaitGroup)
		for i := 0; i < c.CertChecker.Workers; i++ {
			wg.Add(1)
			go checker.processCerts(wg)
		}
		wg.Wait()
		auditlogger.Info(fmt.Sprintf(
			"# Finished processing certificates, sample: %d, good: %d, bad: %d",
			len(checker.issuedReport.Entries),
			checker.issuedReport.GoodCerts,
			checker.issuedReport.BadCerts,
		))
		err = checker.issuedReport.save(c.CertChecker.ReportDirectoryPath)
		cmd.FailOnError(err, "Couldn't save issued certificate report")
	}

	app.Run()
}
