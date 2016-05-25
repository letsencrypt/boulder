// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
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

func (p *expiredAuthzPurger) purgeAuthzs(purgeBefore time.Time, yes bool) (int64, error) {
	if !yes {
		var count int
		err := p.db.SelectOne(&count, `SELECT COUNT(pa.id) FROM pendingAuthorizations AS pa WHERE expires <= ?`, purgeBefore)
		if err != nil {
			return 0, err
		}
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Fprintf(os.Stdout, "\nAbout to purge %d pending authorizations, proceed? [y/N]: ", count)
			text, err := reader.ReadString('\n')
			if err != nil {
				return 0, err
			}
			text = strings.ToLower(text)
			if text != "y\n" && text != "n\n" && text != "\n" {
				continue
			}
			if text == "n\n" || text == "\n" {
				os.Exit(0)
			} else {
				break
			}
		}
	}

	rowsAffected := int64(0)
	for {
		result, err := p.db.Exec(`
			DELETE FROM pendingAuthorizations
			WHERE expires <= ?
			LIMIT ?
			`,
			purgeBefore,
			p.batchSize,
		)
		if err != nil {
			return rowsAffected, err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return rowsAffected, err
		}

		p.stats.Inc("PendingAuthzDeleted", rows, 1.0)
		rowsAffected += rows
		p.log.Info(fmt.Sprintf("Progress: Deleted %d (%d total) expired pending authorizations", rows, rowsAffected))

		if rows < p.batchSize {
			p.log.Info(fmt.Sprintf("Deleted a total of %d expired pending authorizations", rowsAffected))
			return rowsAffected, nil
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
		cli.IntFlag{
			Name:  "batch-size",
			Value: 1000,
			Usage: "Size of batches to do SELECT queries in",
		},
		cli.BoolFlag{
			Name:  "force",
			Usage: "Allows purge of all pending authorizations (dangerous)",
		},
		cli.BoolFlag{
			Name:  "yes",
			Usage: "Skips the purge confirmation",
		},
	}

	app.Action = func(c *cli.Context) {
		configJSON, err := ioutil.ReadFile(c.GlobalString("config"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read config file: %s\n", err)
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
			stats:     stats,
			log:       auditlogger,
			clk:       cmd.Clock(),
			db:        dbMap,
			batchSize: int64(c.GlobalInt("batch-size")),
		}

		if config.ExpiredAuthzPurger.GracePeriod.Duration == 0 && !c.GlobalBool("force") {
			fmt.Fprintln(os.Stderr, "Grace period is 0, refusing to purge all pending authorizations without -force")
			os.Exit(1)
		}
		purgeBefore := purger.clk.Now().Add(-config.ExpiredAuthzPurger.GracePeriod.Duration)
		_, err = purger.purgeAuthzs(purgeBefore, c.GlobalBool("yes"))
		cmd.FailOnError(err, "Failed to purge authorizations")
	}

	err := app.Run(os.Args)
	cmd.FailOnError(err, "Failed to run application")
}
