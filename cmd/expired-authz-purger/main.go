// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/syslog"
	"os"
	"strings"
	"time"

	"github.com/cactus/go-statsd-client/statsd"
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
		err := p.db.SelectOne(&count, `SELECT COUNT(1) FROM pendingAuthorizations AS pa WHERE expires <= ?`, purgeBefore)
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
	batchSize := flag.Int("batch-size", 1000, "Size of batches to do SELECT queries in")
	force := flag.Bool("force", false, "Allows purge of all expired pending authorizations (dangerous)")
	yes := flag.Bool("yes", false, "Skips the purge confirmation")
	dbConnect := flag.String("db-connect", "", "DB Connection URI")
	dbConnectFile := flag.String("db-connect-file", "", "File to read DB Connection URI from")
	maxDBConns := flag.Int("max-db-conns", 0, "Maximum number of DB connections to use")
	gracePeriodStr := flag.String("grace-period", "", "Period after which to purge expired pending authorizations")
	statsdServer := flag.String("statsd-server", "", "Address of StatsD server")
	statsdPrefix := flag.String("statsd-prefix", "boulder", "StatsD stats prefix")
	syslogNetwork := flag.String("syslog-network", "", "Network type to use for syslog messages")
	syslogServer := flag.String("syslog-server", "", "Address of syslog server")
	syslogStdoutLevel := flag.Int("syslog-stdout-level", int(syslog.LOG_DEBUG), "Level of which to print to STDOUT messages sent to syslog")
	flag.Parse()

	// Set up logging
	stats, auditlogger := cmd.StatsAndLogging(
		cmd.StatsdConfig{
			Server: *statsdServer,
			Prefix: *statsdPrefix,
		},
		cmd.SyslogConfig{
			Network:     *syslogNetwork,
			Server:      *syslogServer,
			StdoutLevel: syslogStdoutLevel,
		},
	)
	auditlogger.Info(cmd.Version())

	// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
	defer auditlogger.AuditPanic()

	// Configure DB
	dbConf := cmd.DBConfig{DBConnect: *dbConnect, DBConnectFile: *dbConnectFile}
	dbURL, err := dbConf.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, *maxDBConns)
	cmd.FailOnError(err, "Could not connect to database")
	go sa.ReportDbConnCount(dbMap, metrics.NewStatsdScope(stats, "AuthzPurger"))

	purger := &expiredAuthzPurger{
		stats:     stats,
		log:       auditlogger,
		clk:       cmd.Clock(),
		db:        dbMap,
		batchSize: int64(*batchSize),
	}

	gracePeriod, err := time.ParseDuration(*gracePeriodStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse grace-period argument: %s\n", err)
		os.Exit(1)
	}

	if gracePeriod == 0 && !*force {
		fmt.Fprintln(os.Stderr, "Grace period is 0, refusing to purge all expired pending authorizations without -force")
		os.Exit(1)
	}
	purgeBefore := purger.clk.Now().Add(-gracePeriod)
	_, err = purger.purgeAuthzs(purgeBefore, *yes)
	cmd.FailOnError(err, "Failed to purge authorizations")
}
