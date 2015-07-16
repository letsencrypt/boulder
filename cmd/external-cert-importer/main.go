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


func addOrUpdateCerts(csvFilename string, dbMap *gorp.DbMap) {
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
		
		var count int64
		err = dbMap.SelectOne(&count, "SELECT COUNT(*) FROM externalCerts WHERE SHA1=?", record[0])
		if count > 0 {
			_, err = dbMap.Update(&externalCert)
		} else {
			err = dbMap.Insert(&externalCert)
		}
		
		cmd.FailOnError(err, "Could not insert into database")
	}
}


func addOrUpdateIdentifiers(csvFilename string, dbMap *gorp.DbMap) {
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

		var count int64
		err = dbMap.SelectOne(&count, "SELECT COUNT(*) FROM identifierData WHERE CertSHA1=? AND ReversedName=?", record[0], record[1])
		if count > 0 {
			_, err = dbMap.Update(&identifierData)
		} else {
			err = dbMap.Insert(&identifierData)
		}
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
		Name:   "a, certs-to-add-prefix",
		Value:  "lets-encrypt-export",
		Usage:  "Prefix (including the path) of the three CSV files which will be imported. The filenames are assumed to be of the form lets-encrypt-export-domains.csv, lets-encrypt-export-invalid-certs.csv, and lets-encrypt-export-valid-certs.csv.",
	})


	app.Config = func(c *cli.Context, config cmd.Config) cmd.Config {
		fmt.Println(c.Args())
		config.ExternalCertImporter.CertCSVFilesPrefix = c.GlobalString("a")
		return config
	}

	app.Action = func(c cmd.Config) {
		// Set up logging
		stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
		cmd.FailOnError(err, "Couldn't connect to statsd")

		auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
		cmd.FailOnError(err, "Could not connect to Syslog")

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		blog.SetAuditLogger(auditlogger)

		// Configure DB
		dbMap, err := sa.NewDbMap(c.Common.PolicyDB.Driver, c.Common.PolicyDB.Name)
		cmd.FailOnError(err, "Could not connect to database")

		dbMap.AddTableWithName(core.ExternalCert{}, "externalCerts").SetKeys(false, "SHA1")
		dbMap.AddTableWithName(core.IdentifierData{}, "identifierData").SetKeys(false, "CertSHA1")
		err = dbMap.CreateTablesIfNotExists()
		cmd.FailOnError(err, "Could not create the tables")

		addOrUpdateCerts(c.ExternalCertImporter.CertCSVFilesPrefix + "-valid-certs.csv", dbMap)
		addOrUpdateIdentifiers(c.ExternalCertImporter.CertCSVFilesPrefix + "-domains.csv", dbMap)
		removeInvalidCerts(c.ExternalCertImporter.CertCSVFilesPrefix + "-invalid-certs.csv", dbMap)

		auditlogger.Info(app.VersionString())
	}

	app.Run()
}
