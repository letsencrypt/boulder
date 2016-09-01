package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
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

type eapConfig struct {
	ExpiredAuthzPurger struct {
		cmd.DBConfig

		Statsd cmd.StatsdConfig
		Syslog cmd.SyslogConfig

		GracePeriod cmd.ConfigDuration
		BatchSize   int
	}
}

type expiredAuthzPurger struct {
	stats statsd.Statter
	log   blog.Logger
	clk   clock.Clock
	db    *gorp.DbMap

	batchSize int64
}

func (p *expiredAuthzPurger) purge(table string, yes bool, purgeBefore time.Time) error {
	if !yes {
		var count int
		err := p.db.SelectOne(&count, `SELECT COUNT(1) FROM  AS pa WHERE expires <= ?`, purgeBefore)
		if err != nil {
			return err
		}
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Fprintf(os.Stdout, "\nAbout to purge %d authorizations from %s, proceed? [y/N]: ", count, table)
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
	purged := int64(0)
	for {
		result, err := p.db.Exec(fmt.Sprintf(`
			DELETE FROM %s
			WHERE expires <= ?
			LIMIT ?
			`, table),
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

		p.stats.Inc("PendingAuthzDeleted", rows, 1.0)
		purged += rows
		p.log.Info(fmt.Sprintf("Progress: Deleted %d (%d) expired authorizations from: %s", rows, purged, table))

		if rows < p.batchSize {
			p.log.Info(fmt.Sprintf("Deleted a total of %d expired authorizations from: %s", purged, table))
			return nil
		}
	}
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

	// Set up logging
	stats, auditlogger := cmd.StatsAndLogging(config.ExpiredAuthzPurger.Statsd, config.ExpiredAuthzPurger.Syslog)
	auditlogger.Info(cmd.Version())

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
