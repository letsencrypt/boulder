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
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"gopkg.in/go-gorp/gorp.v2"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
)

type eapConfig struct {
	ExpiredAuthzPurger struct {
		cmd.DBConfig

		Syslog cmd.SyslogConfig

		GracePeriod cmd.ConfigDuration
		BatchSize   int
		Parallelism uint

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

func (p *expiredAuthzPurger) purge(table string, yes bool, purgeBefore time.Time, parallelism int) error {
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

	wg := new(sync.WaitGroup)
	work := make(chan string, len(ids))
	for _, id := range ids {
		work <- id
	}
	close(work)
	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				err := deleteAuthorization(p.db, table, id)
				if err != nil {
					p.log.AuditErr(fmt.Sprintf("Deleting %s: %s", id, err))
				}
			}
		}()
	}
	wg.Wait()

	p.log.Info(fmt.Sprintf("Deleted a total of %d expired authorizations from %s", len(ids), table))
	return nil
}

func deleteAuthorization(db *gorp.DbMap, table, id string) error {
	// Delete challenges + authorization. We delete challenges first and fail out
	// if that doesn't succeed so that we don't ever orphan challenges which would
	// require a relatively expensive join to then find.
	_, err := db.Exec("DELETE FROM challenges WHERE authorizationID = ?", id)
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
	_, err = db.Exec(query, id)
	if err != nil {
		return err
	}
	return nil
}

func (p *expiredAuthzPurger) purgeAuthzs(purgeBefore time.Time, yes bool, parallelism int) error {
	for _, table := range []string{"pendingAuthorizations", "authz"} {
		err := p.purge(table, yes, purgeBefore, parallelism)
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
	scope, auditlogger := cmd.StatsAndLogging(config.ExpiredAuthzPurger.Syslog)
	auditlogger.Info(cmd.VersionString())

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
	if config.ExpiredAuthzPurger.Parallelism < 1 {
		fmt.Fprintln(os.Stderr, "Parallelism field in config must be set to non-zero")
		os.Exit(1)
	}
	purgeBefore := purger.clk.Now().Add(-config.ExpiredAuthzPurger.GracePeriod.Duration)
	err = purger.purgeAuthzs(purgeBefore, *yes, int(config.ExpiredAuthzPurger.Parallelism))
	cmd.FailOnError(err, "Failed to purge authorizations")
}
