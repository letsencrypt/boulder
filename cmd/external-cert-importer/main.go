// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"time"
	"fmt"
	"encoding/csv"
	"os"
	"io"
	"encoding/hex"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

var datestamp_format string = "2006-01-02 15:04:05"


func addCerts(csvFilename string, dbMap *gorp.DbMap) {
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
			
		notAfter, err := time.Parse(datestamp_format, record[3])
		spkiBytes, err := hex.DecodeString(record[4])
		lastUpdated, err := time.Parse(datestamp_format, record[7])
		certDER, err := hex.DecodeString(record[8])
		
		externalCert := core.ExternalCert{
			SHA1: record[0],
			Issuer: record[1],
			Subject: record[2],
			NotAfter: notAfter,
			SPKI: spkiBytes,
			Valid: record[5]=="1",
			EV: record[6]=="1",
			LastUpdated: lastUpdated,
			CertDER: certDER,
		}

		err = dbMap.Insert(&externalCert)

		cmd.FailOnError(err, "Could not insert into database")
	}
}


func addIdentifiers(csvFilename string, dbMap *gorp.DbMap) {
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

		lastUpdated, err := time.Parse(datestamp_format, record[2])

		identifierData := core.IdentifierData{
			ReversedName: record[1],
			CertSHA1: record[0],
			LastUpdated: lastUpdated,
		}

		err = dbMap.Insert(&identifierData)
	}
}


func removeInvalidCerts(csvFilename string, dbMap *gorp.DbMap) {
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

		_, err = dbMap.Delete(&identifierData)
		_, err = dbMap.Delete(&externalCert)
	}
}


func main() {
	app := cmd.NewAppShell("external-cert-importer")

	app.App.Flags = append(app.App.Flags, cli.StringFlag{
		Name:  "a, certs-to-import-csv-file",
		Value: "ssl-observatory-valid-certs.csv",
		Usage: "The CSV file containing the valid certs to import.",
	}, cli.StringFlag{
		Name:  "d, domains-to-import-csv-file",
		Value: "ssl-observatory-domains.csv",
		Usage: "The CSV file containing the domains associated with the certs that are being imported.",
	}, cli.StringFlag{
		Name:  "r, certs-to-remove-csv-file",
		Value: "ssl-observatory-invalid-certs.csv",
		Usage: "The CSV file Containing now invalid certs which should be removed.",
	})


	app.Config = func(c *cli.Context, config cmd.Config) cmd.Config {
		fmt.Println(c.Args())
		config.ExternalCertImporter.CertsToImportCSVFilename = c.GlobalString("a")
		config.ExternalCertImporter.DomainsToImportCSVFilename = c.GlobalString("d")
		config.ExternalCertImporter.CertsToRemoveCSVFilename = c.GlobalString("r")
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
		dbMap, err := sa.NewDbMap(c.Common.PolicyDB.Driver, c.Common.PolicyDB.Name)
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
		addCerts(c.ExternalCertImporter.CertsToImportCSVFilename, dbMap)
		addIdentifiers(c.ExternalCertImporter.DomainsToImportCSVFilename, dbMap)
		removeInvalidCerts(c.ExternalCertImporter.CertsToRemoveCSVFilename, dbMap)
	}

	app.Run()
}
