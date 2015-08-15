// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

const datestampFormat string = "2006-01-02 15:04:05"

func addCerts(csvFilename string, dbMap *gorp.DbMap, stats statsd.Statter, statsRate float32) {
	file, err := os.Open(csvFilename)
	cmd.FailOnError(err, "Could not open the file for reading")
	csvReader := csv.NewReader(file)

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println("Error:", err)
			return
		}

		notAfter, err := time.Parse(datestampFormat, record[3])
		spkiBytes, err := hex.DecodeString(record[4])
		certDER, err := hex.DecodeString(record[7])

		externalCert := core.ExternalCert{
			SHA1:     record[0],
			Issuer:   record[1],
			Subject:  record[2],
			NotAfter: notAfter,
			SPKI:     spkiBytes,
			Valid:    record[5] == "1",
			EV:       record[6] == "1",
			CertDER:  certDER,
		}

		importStart := time.Now()
		err = dbMap.Insert(&externalCert)
		stats.TimingDuration("ExistingCert.CertImportTime", time.Since(importStart), statsRate)
		stats.Inc("ExistingCert.CertsImported", 1, statsRate)
	}
}

func addIdentifiers(csvFilename string, dbMap *gorp.DbMap, stats statsd.Statter, statsRate float32) {
	file, err := os.Open(csvFilename)
	cmd.FailOnError(err, "Could not open the file for reading")
	csvReader := csv.NewReader(file)

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println("Error:", err)
			return
		}

		identifierData := core.IdentifierData{
			ReversedName: record[1],
			CertSHA1:     record[0],
		}

		importStart := time.Now()
		err = dbMap.Insert(&identifierData)
		stats.TimingDuration("ExistingCert.DomainImportTime", time.Since(importStart), statsRate)
		stats.Inc("ExistingCert.DomainsImported", 1, statsRate)
	}
}

func removeInvalidCerts(csvFilename string, dbMap *gorp.DbMap, stats statsd.Statter, statsRate float32) {
	file, err := os.Open(csvFilename)
	cmd.FailOnError(err, "Could not open the file for reading")
	csvReader := csv.NewReader(file)

	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println("Error:", err)
			return
		}

		identifierData := core.IdentifierData{
			CertSHA1: record[0],
		}
		externalCert := core.ExternalCert{
			SHA1: record[0],
		}

		deleteStart := time.Now()
		_, err = dbMap.Delete(&identifierData)
		stats.TimingDuration("ExistingCert.DomainDeleteTime", time.Since(deleteStart), statsRate)
		_, err = dbMap.Delete(&externalCert)
		stats.TimingDuration("ExistingCert.CertDeleteTime", time.Since(deleteStart), statsRate)
		stats.Inc("ExistingCert.CertsDeleted", 1, statsRate)
	}
}

func main() {
	app := cmd.NewAppShell("external-cert-importer")

	app.App.Flags = append(app.App.Flags, cli.StringFlag{
		Name:  "a, valid-certs-file",
		Value: "ssl-observatory-valid-certs.csv",
		Usage: "The CSV file containing the valid certs to import.",
	}, cli.StringFlag{
		Name:  "d, domains-file",
		Value: "ssl-observatory-domains.csv",
		Usage: "The CSV file containing the domains associated with the certs that are being imported.",
	}, cli.StringFlag{
		Name:  "r, invalid-certs-file",
		Value: "ssl-observatory-invalid-certs.csv",
		Usage: "The CSV file Containing now invalid certs which should be removed.",
	}, cli.Float64Flag{
		Name:  "statsd-rate",
		Value: 0.1,
		Usage: "A floating point number between 0 and 1 representing the rate at which the statsd client will send data.",
	})

	app.Config = func(c *cli.Context, config cmd.Config) cmd.Config {
		fmt.Println(c.Args())
		config.ExternalCertImporter.CertsToImportCSVFilename = c.GlobalString("a")
		config.ExternalCertImporter.DomainsToImportCSVFilename = c.GlobalString("d")
		config.ExternalCertImporter.CertsToRemoveCSVFilename = c.GlobalString("r")
		config.ExternalCertImporter.StatsdRate = float32(math.Min(math.Max(c.Float64("statsd-rate"), 0.0), 1.0))
		return config
	}

	app.Action = func(c cmd.Config) {
		// Set up logging
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		blog.SetAuditLogger(auditlogger)

		// Configure DB
		dbMap, err := sa.NewDbMap(c.PA.DBConnect)
		cmd.FailOnError(err, "Could not connect to database")

		dbMap.AddTableWithName(core.ExternalCert{}, "externalCerts").SetKeys(false, "SHA1")
		dbMap.AddTableWithName(core.IdentifierData{}, "identifierData").SetKeys(false, "CertSHA1")
		err = dbMap.CreateTablesIfNotExists()
		cmd.FailOnError(err, "Could not create the tables")

		// Note that this order of operations is intentional: we first add
		// new certs to the database. Then, since certs are identified by
		// the entries in the identifiers table, we add those. Then, we
		// can remove invalid certs (which first removes the associated
		// identifiers).
		addCerts(c.ExternalCertImporter.CertsToImportCSVFilename, dbMap, stats, c.ExternalCertImporter.StatsdRate)
		addIdentifiers(c.ExternalCertImporter.DomainsToImportCSVFilename, dbMap, stats, c.ExternalCertImporter.StatsdRate)
		removeInvalidCerts(c.ExternalCertImporter.CertsToRemoveCSVFilename, dbMap, stats, c.ExternalCertImporter.StatsdRate)
	}

	app.Run()
}
