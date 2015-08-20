// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

const (
	good = "valid"
	bad  = "invalid"
)

type report struct {
	Validity string `json:"validity"`
	Problem  string `json:"problem,omitempty"`
}

type certChecker struct {
	dbMap        *gorp.DbMap
	certs        chan core.Certificate
	sampleReport map[string]report
	goodCerts    int64
	badCerts     int64
}

func newChecker(dbMap *gorp.DbMap) certChecker {
	return certChecker{
		dbMap:        dbMap,
		sampleReport: make(map[string]report),
	}
}

func (c *certChecker) getSerials(lastScan *time.Time) ([]string, error) {
	query := "SELECT serial FROM certificates"
	queryArgs := make(map[string]interface{})
	if lastScan != nil {
		query = query + " WHERE issued > :issued"
		queryArgs["issued"] = *lastScan
	} else {
		// should probably log this
	}
	var serials []string
	_, err := c.dbMap.Select(&serials, query, queryArgs)
	return serials, err
}

func (c *certChecker) pickSerials(sampleFraction float64, lastScan *time.Time) ([]string, error) {
	serials, err := c.getSerials(lastScan)
	if err != nil {
		return nil, err
	}
	// shuffle serials
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range serials {
		j := rand.Intn(i + 1)
		serials[i], serials[j] = serials[j], serials[i]
	}
	sampleSize := int(float64(len(serials)) * sampleFraction)
	if sampleSize == 0 || sampleSize > len(serials) {
		// probably log this fact
		sampleSize = len(serials)
	}
	return serials[0:sampleSize], nil
}

func (c *certChecker) getCerts(serials []string) error {
	var certs []core.Certificate
	_, err := c.dbMap.Select(
		&certs,
		fmt.Sprintf("SELECT * FROM certificates WHERE serial IN ('%s')", strings.Join(serials, "','")),
	)
	if err != nil {
		return err
	}
	c.certs = make(chan core.Certificate, len(certs))
	for _, cert := range certs {
		c.certs <- cert
	}
	// Close channel so range operations won't block when the channel empties out
	close(c.certs)
	return nil
}

func (c *certChecker) processCerts(wg *sync.WaitGroup) {
	for cert := range c.certs {
		// ???
		fmt.Println("CERT:", cert.Serial)

		c.sampleReport[cert.Serial] = report{Validity: good}
		atomic.AddInt64(&c.goodCerts, 1)
	}
	wg.Done()
}

func main() {
	app := cmd.NewAppShell("cert-checker")
	app.App.Flags = append(app.App.Flags, cli.StringFlag{
		Name:  "last-check",
		Usage: "The date of the last scan in the format DDMMYY",
	}, cli.IntFlag{
		Name:  "workers",
		Value: 5,
		Usage: "The number of cocurrent workers used to process certificates",
	}, cli.Float64Flag{
		Name:  "sample-fraction",
		Value: 0.03,
		Usage: "A positive floating point number indicating the fraction of certificates to check",
	}, cli.StringFlag{
		Name:  "report-path",
		Usage: "The path to write a JSON report on the certificates checks to (if no path is provided the report will not be written out)",
	}, cli.StringFlag{
		Name:  "sql-uri",
		Usage: "SQL URI if not provided in the configuration file",
	})

	app.Config = func(c *cli.Context, config cmd.Config) cmd.Config {
		lastCheck := c.GlobalString("last-check")
		if lastCheck != "" {
			t, err := time.Parse("layout", lastCheck)
			cmd.FailOnError(err, "Couldn't parse last check date")
			config.CertChecker.LastCheck = &t
		}
		config.CertChecker.ReportPath = c.GlobalString("report-path")
		if connect := c.GlobalString("sql-uri"); connect != "" {
			config.CertChecker.DBConnect = connect
		}
		config.CertChecker.SampleFraction = c.Float64("sample-fraction")
		config.CertChecker.Workers = c.Int("workers")
		return config
	}

	app.Action = func(c cmd.Config) {
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		blog.SetAuditLogger(auditlogger)
		auditlogger.Info(app.VersionString())

		dbMap, err := sa.NewDbMap(c.CertChecker.DBConnect)
		cmd.FailOnError(err, "Could not connect to database")

		checker := newChecker(dbMap)
		auditlogger.Info("# Picking certificate sample")
		sampleSerials, err := checker.pickSerials(c.CertChecker.SampleFraction, c.CertChecker.LastCheck)
		cmd.FailOnError(err, "Failed to pick serial sample")

		auditlogger.Info("# Getting sample")
		err = checker.getCerts(sampleSerials)
		cmd.FailOnError(err, "Failed to get sample certificates")

		if c.CertChecker.Workers > len(checker.certs) {
			c.CertChecker.Workers = len(checker.certs)
		}
		auditlogger.Info(fmt.Sprintf("# Processing sample, %d certificates using %d workers", len(checker.certs), c.CertChecker.Workers))
		wg := new(sync.WaitGroup)
		for i := 0; i < c.CertChecker.Workers; i++ {
			wg.Add(1)
			go checker.processCerts(wg)
		}
		wg.Wait()
		auditlogger.Info(fmt.Sprintf(
			"# Finished processing certificates, sample: %d, good: %d, bad: %d",
			len(checker.sampleReport),
			checker.goodCerts,
			checker.badCerts,
		))
	}

	app.Run()
}
