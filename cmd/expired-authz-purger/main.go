package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"gopkg.in/go-gorp/gorp.v2"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

type eapConfig struct {
	ExpiredAuthzPurger struct {
		cmd.DBConfig

		Syslog cmd.SyslogConfig

		GracePeriod cmd.ConfigDuration
		BatchSize   int
		MaxAuthzs   int
		Parallelism uint

		Features map[string]bool
	}
}

type expiredAuthzPurger struct {
	log blog.Logger
	clk clock.Clock
	db  *gorp.DbMap

	batchSize int64
}

// purge looks up pending or finalized authzs (depending on the value of
// `table`) that expire before `purgeBefore`, using `parallelism`
// goroutines. It will delete a maximum of `max` authzs.
// Neither table has an index on `expires` by itself, so we just iterate through
// the table with LIMIT and OFFSET using the default ordering. Note that this
// becomes expensive once the earliest set of authzs has been purged, since the
// database will have to scan through many rows before it finds some that meet
// the expiration criteria. When we move to better authz storage (#2620), we
// will get an appropriate index that will make this cheaper.
func (p *expiredAuthzPurger) purge(table string, purgeBefore time.Time, parallelism int, max int) error {
	var query string
	switch table {
	case "pendingAuthorizations":
		query = "SELECT id FROM pendingAuthorizations WHERE id >= :id AND expires <= :expires ORDER BY id LIMIT :limit"
	case "authz":
		query = "SELECT id FROM authz WHERE id >= :id AND expires <= :expires ORDER BY id LIMIT :limit"
	}

	done := make(chan int)
	work := make(chan string)
	go func() {
		// id starts as "", which is smaller than all other ids.
		var id string
		var count int
		for count < max {
			var idBatch []string
			_, err := p.db.Select(
				&idBatch,
				query,
				map[string]interface{}{
					"id":      id,
					"expires": purgeBefore,
					"limit":   p.batchSize,
				},
			)
			if err != nil && err != sql.ErrNoRows {
				p.log.AuditErrf("Getting a batch: %s", err)
				time.Sleep(10)
				continue
			}
			for _, v := range idBatch {
				work <- v
				count += 1
				// Start the next query at the highest id we saw in this batch.
				id = v
			}
			p.log.Infof("Deleted %d authzs from %s so far", count, table)
			if len(idBatch) < int(p.batchSize) {
				break
			}
		}
		close(work)
		done <- count
	}()

	wg := new(sync.WaitGroup)
	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				err := deleteAuthorization(p.db, table, id)
				if err != nil {
					p.log.AuditErrf("Deleting %s: %s", id, err)
				}
			}
		}()
	}

	count := <-done
	wg.Wait()

	p.log.Infof("Deleted a total of %d expired authorizations from %s", count, table)
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

func (p *expiredAuthzPurger) purgeAuthzs(purgeBefore time.Time, parallelism int, max int) error {
	// Purge authz first because it tends to be bigger and in more need of
	// purging.
	for _, table := range []string{"authz", "pendingAuthorizations"} {
		err := p.purge(table, purgeBefore, parallelism, max)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
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

	logger := cmd.NewLogger(config.ExpiredAuthzPurger.Syslog)
	logger.Info(cmd.VersionString())

	defer logger.AuditPanic()

	// Configure DB
	dbURL, err := config.ExpiredAuthzPurger.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, config.ExpiredAuthzPurger.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Could not connect to database")
	sa.SetSQLDebug(dbMap, logger)

	purger := &expiredAuthzPurger{
		log:       logger,
		clk:       cmd.Clock(),
		db:        dbMap,
		batchSize: int64(config.ExpiredAuthzPurger.BatchSize),
	}

	if config.ExpiredAuthzPurger.GracePeriod.Duration == 0 {
		fmt.Fprintln(os.Stderr, "Grace period is 0, refusing to purge all pending authorizations")
		os.Exit(1)
	}
	if config.ExpiredAuthzPurger.Parallelism == 0 {
		fmt.Fprintln(os.Stderr, "Parallelism field in config must be set to non-zero")
		os.Exit(1)
	}
	purgeBefore := purger.clk.Now().Add(-config.ExpiredAuthzPurger.GracePeriod.Duration)
	logger.Info("Beginning purge")
	err = purger.purgeAuthzs(purgeBefore, int(config.ExpiredAuthzPurger.Parallelism),
		int(config.ExpiredAuthzPurger.MaxAuthzs))
	cmd.FailOnError(err, "Failed to purge authorizations")
}
