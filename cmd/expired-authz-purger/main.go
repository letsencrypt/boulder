package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"gopkg.in/go-gorp/gorp.v2"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
)

const clientName = "ExpiredAuthzPurger"

type eapConfig struct {
	ExpiredAuthzPurger struct {
		cmd.DBConfig

		Statsd cmd.StatsdConfig
		Syslog cmd.SyslogConfig

		GracePeriod cmd.ConfigDuration
		BatchSize   int

		Features map[string]bool
	}
}

type expiredAuthzPurger struct {
	stats metrics.Scope
	log   blog.Logger
	clk   clock.Clock
	db    *gorp.DbMap

	batchSize int64
}

func (p *expiredAuthzPurger) purge(table string, yes bool, purgeBefore time.Time) error {
	var ids []string
	for {
		var idBatch []string
		var query string
		switch table {
		case "pendingAuthorizations":
			query = "SELECT id FROM pendingAuthorizations WHERE expires <= ? LIMIT ? OFFSET ?"
		case "authz":
			query = "SELECT id FROM authz WHERE expires <= ? LIMIT ? OFFSET ?"
		}
		_, err := p.db.Select(
			&idBatch,
			query,
			purgeBefore,
			p.batchSize,
			len(ids),
		)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if len(idBatch) == 0 {
			break
		}
		ids = append(ids, idBatch...)
	}

	if !yes {
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Fprintf(
				os.Stdout,
				"\nAbout to purge %d authorizations from %s and all associated challenges, proceed? [y/N]: ",
				len(ids),
				table,
			)
			text, err := reader.ReadString('\n')
			if err != nil {
				return err
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

	for _, id := range ids {
		// Delete challenges + authorization. We delete challenges first and fail out
		// if that doesn't succeed so that we don't ever orphan challenges which would
		// require a relatively expensive join to then find.
		_, err := p.db.Exec("DELETE FROM challenges WHERE authorizationID = ?", id)
		if err != nil {
			return err
		}
		var query string
		switch table {
		case "pendingAuthorizations":
			query = "DELETE FROM pendingAuthorizations WHERE id = ?"
		case "authz":
			query = "DELETE FROM authz WHERE id = ?"
		}
		_, err = p.db.Exec(query, id)
		if err != nil {
			return err
		}
	}

	p.log.Info(fmt.Sprintf("Deleted a total of %d expired authorizations from %s", len(ids), table))
	return nil
}

func (p *expiredAuthzPurger) purgeAuthzs(purgeBefore time.Time, yes bool) error {
	for _, table := range []string{"pendingAuthorizations", "authz"} {
		err := p.purge(table, yes, purgeBefore)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	yes := flag.Bool("yes", false, "Skips the purge confirmation")
	configPath := flag.String("config", "config.json", "Path to Boulder configuration file")
	flag.Parse()

	configJSON, err := ioutil.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config file '%s': %s\n", *configPath, err)
		os.Exit(1)
	}

	var config eapConfig
	err = json.Unmarshal(configJSON, &config)
	cmd.FailOnError(err, "Failed to parse config")
	err = features.Set(config.ExpiredAuthzPurger.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	// Set up logging
	stats, auditlogger := cmd.StatsAndLogging(config.ExpiredAuthzPurger.Statsd, config.ExpiredAuthzPurger.Syslog)
	scope := metrics.NewStatsdScope(stats, "AuthzPurger")
	auditlogger.Info(cmd.VersionString(clientName))

	defer auditlogger.AuditPanic()

	// Configure DB
	dbURL, err := config.ExpiredAuthzPurger.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, config.ExpiredAuthzPurger.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Could not connect to database")
	go sa.ReportDbConnCount(dbMap, scope)

	purger := &expiredAuthzPurger{
		stats:     scope,
		log:       auditlogger,
		clk:       cmd.Clock(),
		db:        dbMap,
		batchSize: int64(config.ExpiredAuthzPurger.BatchSize),
	}

	if config.ExpiredAuthzPurger.GracePeriod.Duration == 0 {
		fmt.Fprintln(os.Stderr, "Grace period is 0, refusing to purge all pending authorizations")
		os.Exit(1)
	}
	purgeBefore := purger.clk.Now().Add(-config.ExpiredAuthzPurger.GracePeriod.Duration)
	err = purger.purgeAuthzs(purgeBefore, *yes)
	cmd.FailOnError(err, "Failed to purge authorizations")
}
