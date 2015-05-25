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
	"strconv"
	"sort"
	"strings"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"

	// Load both drivers to allow configuring either
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"

	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
)

var reasons map[int]string = map[int]string{
	0:  "unspecified",
	1:  "keyCompromise",
	2:  "cACompromise",
	3:  "affiliationChanged",
	4:  "superseded",
	5:  "cessationOfOperation",
	6:  "certificateHold",
	// 7 is unused
	8:  "removeFromCRL", // needed?
	9:  "privilegeWithdrawn",
	10: "aAcompromise",
}

func loadConfig(c *cli.Context) (config cmd.Config, err error) {
	configFileName := c.GlobalString("config")
	configJSON, err := ioutil.ReadFile(configFileName)
	if err != nil {
		return
	}

	err = json.Unmarshal(configJSON, &config)
	return
}

func setupContext(context *cli.Context) (rpc.CertificateAuthorityClient, *blog.AuditLogger, *gorp.DbMap) {
	c, err := loadConfig(context)
	cmd.FailOnError(err, "Failed to load Boulder configuration")

	ch := cmd.AmqpChannel(c.AMQP.Server)

	cac, err := rpc.NewCertificateAuthorityClient(c.AMQP.CA.Client, c.AMQP.CA.Server, ch)
	cmd.FailOnError(err, "Unable to create CA client")

	stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
	cmd.FailOnError(err, "Couldn't connect to statsd")

	auditlogger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
	cmd.FailOnError(err, "Could not connect to Syslog")

	dbMap, err := sa.NewDbMap(c.Revoker.DBDriver, c.Revoker.DBName)
	cmd.FailOnError(err, "Couldn't setup database connection")

	dbMap.AddTableWithName(core.DeniedCsr{}, "deniedCsrs").SetKeys(true, "ID")
	err = dbMap.CreateTablesIfNotExists()
	cmd.FailOnError(err, "Could not create the deniedCsrs table")

	return cac, auditlogger, dbMap
}

func AddDeniedNames(tx *gorp.Transaction, names []string) (err error) {
	sort.Strings(names)
	deniedCSR := &core.DeniedCsr{Names: strings.ToLower(strings.Join(names, ","))}

	err = tx.Insert(deniedCSR)
	if err != nil {
		tx.Rollback()
		return
	}

	err = tx.Commit()
	return
}

func revokeBySerial(serial string, reasonCode int, deny bool, cac rpc.CertificateAuthorityClient, auditlogger *blog.AuditLogger, tx *gorp.Transaction) {
	if reasonCode < 0 || reasonCode == 7 || reasonCode > 10 {
		panic(fmt.Sprintf("Invalid reason code: %d", reasonCode))
	}

	if deny {
		// Retrieve DNS names associated with serial
		var certificate core.Certificate
		err := tx.SelectOne(&certificate, "SELECT * FROM certificates WHERE serial = :serial",
			map[string]interface{}{"serial": serial})
		cmd.FailOnError(err, fmt.Sprintf("Couldn't retrieve certificate with serial %s", serial))
		cert, err := x509.ParseCertificate(certificate.DER)
		cmd.FailOnError(err, "Couldn't parse certificate")
		err = AddDeniedNames(tx, append(cert.DNSNames, cert.Subject.CommonName))
		cmd.FailOnError(err, "Couldn't add DNS names to denied CSR table")
	}

	err := cac.RevokeCertificate(serial, reasonCode)
	cmd.FailOnError(err, "Couldn't revoke certificate serial")

	auditlogger.Info(fmt.Sprintf("Revoked certificate %s with reason '%s'", serial, reasons[reasonCode]))
}

func revokeByReg(regID int, reasonCode int, deny bool, cac rpc.CertificateAuthorityClient, auditlogger *blog.AuditLogger, tx *gorp.Transaction) {
	_, err := tx.Get(core.Registration{}, regID)
	if err != nil {
		tx.Rollback()
	}
	cmd.FailOnError(err, "Couldn't retrieve registration")

	var certs []core.Certificate
	_, err = tx.Select(certs, "SELECT serial FROM certificates WHERE registrationID = :regID", map[string]interface{}{"regID": regID})
	cmd.FailOnError(err, "Couldn't retrieve certificates")

	for _, cert := range certs {
		revokeBySerial(cert.Serial, reasonCode, deny, cac, auditlogger, tx)
	}
}

var version string = "0.0.1"

func main() {
	app := cli.NewApp()
	app.Name = "admin-revoker"
	app.Version = version

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Value:  "config.json",
			EnvVar: "BOULDER_CONFIG",
			Usage: "Path to Boulder JSON configuration file",
		},
		cli.BoolFlag{
			Name:  "deny-future",
			Usage: "Add certificate DNS names to the denied list",
		},
	}
	app.Commands = []cli.Command{
		{
			Name: "serial-revoke",
			Usage: "Revoke a single certificate by the hex serial number",
			Action: func(c *cli.Context) {
				// 1: serial,  2: reasonCode (3: deny flag)
				serial := c.Args().First()
				reasonCode, err := strconv.Atoi(c.Args().Get(2))
				cmd.FailOnError(err, "Reason code argument must be a integer")
				deny := c.GlobalBool("deny")

				cac, auditlogger, dbMap := setupContext(c)
				// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
				defer auditlogger.AuditPanic()
				blog.SetAuditLogger(auditlogger)

				tx, err := dbMap.Begin()
				if err != nil {
					tx.Rollback()
				}
				cmd.FailOnError(err, "Couldn't being transaction")

				revokeBySerial(serial, reasonCode, deny, cac, auditlogger, tx)

				err = tx.Commit()
				cmd.FailOnError(err, "Couldn't cleanly close transaction")
			},
		},
		{
			Name: "reg-revoke",
			Usage: "Revoke all certificates associated with a registration ID",
			Action: func(c *cli.Context) {
				// 1: registration ID,  2: reasonCode (3: deny flag)
				regID, err := strconv.Atoi(c.Args().First())
				cmd.FailOnError(err, "Registration ID argument must be a integer")
				reasonCode, err := strconv.Atoi(c.Args().Get(2))
				cmd.FailOnError(err, "Reason code argument must be a integer")
				deny := c.GlobalBool("deny")

				cac, auditlogger, dbMap := setupContext(c)
				// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
				defer auditlogger.AuditPanic()
				blog.SetAuditLogger(auditlogger)
				
				tx, err := dbMap.Begin()
				if err != nil {
					tx.Rollback()
				}
				cmd.FailOnError(err, "Couldn't being transaction")

				revokeByReg(regID, reasonCode, deny, cac, auditlogger, tx)

				err = tx.Commit()
				cmd.FailOnError(err, "Couldn't cleanly close transaction")
			},
		},
		{
			Name: "list-reasons",
			Usage: "List possible revocation reason codes",
			Action: func(c *cli.Context) {
				var codes []int
				for k, _ := range reasons {
					codes = append(codes, k)
				}
				sort.Ints(codes)
				fmt.Println("Revocation reason codes\n-----------------------\n")
				for _, k := range codes {
					fmt.Printf("%d: %s\n", k, reasons[k])
				}
			},
		},
	}

	err := app.Run(os.Args)
	cmd.FailOnError(err, "Failed to run application")
}