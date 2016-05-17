// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/cactus/go-statsd-client/statsd"
	"github.com/codegangsta/cli"
	"github.com/jmhodges/clock"
	"gopkg.in/gorp.v1"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
)

type expiredAuthzPurger struct {
	stats statsd.Statter
	log   blog.Logger
	clk   clock.Clock
	db    *gorp.DbMap

	batchSize int64
}

func (p *expiredAuthzPurger) setDefaults() {
	if p.batchSize == 0 {
		p.batchSize = 1000
	}
}

func (p *expiredAuthzPurger) purgeAuthzs(purgeBefore time.Time) error {
	tx, err := p.db.Begin()
	if err != nil {
		return err
	}

	rowsAffected := int64(0)

	for {
		result, err := tx.Exec(`
			DELETE FROM pendingAuthorizations
			WHERE expires < ?
			LIMIT ?
			`,
			purgeBefore,
			p.batchSize,
		)
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}

		rowsAffected += rows
		p.log.Warning(fmt.Sprintf("Progress: Deleted %d (%d) expired pending authorizations", rows, rowsAffected))

		if rows < p.batchSize {
			p.log.Info(fmt.Sprintf("Deleted a total of %d expired pending authorizations", rowsAffected))
			return nil
		}
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "expired-authz-purger"
	app.Usage = "Purge expired pending authorizations from the database"
	app.Version = cmd.Version()
	app.Author = "Boulder contributors"
	app.Email = "ca-dev@letsencrypt.org"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Value:  "config.json",
			EnvVar: "BOULDER_CONFIG",
			Usage:  "Path to Boulder JSON configuration file",
		},
	}

	app.Action = func(c *cli.Context) {
		configFileName := c.GlobalString("config")

		if configFileName == "" {
			fmt.Println("Option -config (or BOULDER_CONFIG) is required")
			return
		}

		configJSON, err := ioutil.ReadFile(configFileName)
		if err != nil {
			fmt.Printf("Failed to read config file: %s\n", err)
			return
		}

		var config cmd.Config
		err = json.Unmarshal(configJSON, &config)

		// Set up logging
		stats, auditlogger := cmd.StatsAndLogging(config.Statsd, config.Syslog)
		auditlogger.Info(app.Version)

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		// Configure DB
		dbURL, err := config.ExpiredAuthzPurger.DBConfig.URL()
		cmd.FailOnError(err, "Couldn't load DB URL")
		dbMap, err := sa.NewDbMap(dbURL, config.ExpiredAuthzPurger.DBConfig.MaxDBConns)
		cmd.FailOnError(err, "Could not connect to database")
		go sa.ReportDbConnCount(dbMap, metrics.NewStatsdScope(stats, "AuthzPurger"))

		purger := &expiredAuthzPurger{
			stats: stats,
			log:   auditlogger,
			clk:   cmd.Clock(),
			db: dbMap,
		}
		purger.setDefaults()

		purgeBefore := purger.clk.Now().Add(-config.ExpiredAuthzPurger.GracePeriod.Duration)
		err = purger.purgeAuthzs(purgeBefore)
		cmd.FailOnError(err, "Failed to purge authorizations")
	}

	err := app.Run(os.Args)
	cmd.FailOnError(err, "Failed to run application")
}
