package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
	"github.com/prometheus/client_golang/prometheus"
)

type eapConfig struct {
	ExpiredAuthzPurger struct {
		cmd.DBConfig

		DebugAddr string

		Syslog cmd.SyslogConfig

		GracePeriod cmd.ConfigDuration
		BatchSize   int
		MaxAuthzs   int
		Parallelism uint
		// MaxDPS controls the maximum number of deletes which will be performed
		// per second in total from both the pendingAuthorizations and authz tables.
		// This can be used to reduce the replication lag caused by creating very
		// large numbers of delete statements.
		MaxDPS int
		// PendingCheckpointFile is the path to a file which is used to store the
		// last pending authorization ID which was deleted. If path is to a file
		// which does not exist it will be created.
		PendingCheckpointFile string
		// FinalCheckpointFile is the path to a file which is used to store the
		// last authorization ID which was deleted. If path is to a file
		// which does not exist it will be created.
		FinalCheckpointFile string

		Features map[string]bool
	}
}

type eapDB interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Select(i interface{}, query string, args ...interface{}) ([]interface{}, error)
}

var deletedStat = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "eap_authorizations_deleted",
		Help: "Number of authorizations the EAP has deleted.",
	},
	[]string{"type"},
)

type expiredAuthzPurger struct {
	log blog.Logger
	clk clock.Clock
	db  eapDB

	batchSize int64
}

// loadCheckpoint reads a string (which is assumed to be an authorization ID)
// from the file at the provided path and returns it to the caller. If the
// file does not exist an error is not returned and the returned ID is an
// empty string.
func loadCheckpoint(checkpointFile string) (string, error) {
	content, err := ioutil.ReadFile(checkpointFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(content), nil
}

// saveCheckpoint atomically writes the provided ID to the provided file. The
// method os.Rename makes use of the renameat syscall to atomically replace
// one file with another. It creates a temporary file in a temporary directory
// before using os.Rename to replace the old file with the new one.
func saveCheckpoint(checkpointFile, id string) error {
	tmpDir, err := ioutil.TempDir("", "checkpoint-tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	tmp, err := ioutil.TempFile(tmpDir, "checkpoint-atomic")
	if err != nil {
		return err
	}
	if _, err = tmp.Write([]byte(id)); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), checkpointFile)
}

// getWork selects a set of authorizations that expired before purgeBefore, bounded by batchSize,
// that have IDs that are more than initialID from either the pendingAuthorizations or authz tables
// and adds them to the work channel. It returns the last ID it selected and the number of IDs it
// added to the work channel or an error.
func (p *expiredAuthzPurger) getWork(work chan string, query string, initialID string, purgeBefore time.Time, batchSize int64) (string, int, error) {
	var idBatch []string
	_, err := p.db.Select(
		&idBatch,
		query,
		map[string]interface{}{
			"id":      initialID,
			"expires": purgeBefore,
			"limit":   batchSize,
		},
	)
	if err != nil && err != sql.ErrNoRows {
		return "", 0, fmt.Errorf("Getting a batch: %s", err)
	}
	if len(idBatch) == 0 {
		return initialID, 0, nil
	}
	var count int
	var lastID string
	for _, v := range idBatch {
		work <- v
		count++
		lastID = v
	}
	return lastID, count, nil
}

// deleteAuthorizations reads from the work channel and deletes each authorization
// from either the pendingAuthorization or authz tables. If maxDPS is more than 0
// it will throttle the number of DELETE statements it generates to the passed rate.
func (p *expiredAuthzPurger) deleteAuthorizations(work chan string, maxDPS int, parallelism int, table string, checkpointFile string) {
	wg := new(sync.WaitGroup)
	deleted := int64(0)
	var ticker *time.Ticker
	if maxDPS > 0 {
		ticker = time.NewTicker(time.Duration(float64(time.Second) / float64(maxDPS)))
	}
	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				if ticker != nil {
					<-ticker.C
				}
				err := deleteAuthorization(p.db, table, id)
				if err != nil {
					p.log.AuditErrf("Deleting %s: %s", id, err)
				}
				numDeleted := atomic.AddInt64(&deleted, 1)
				// Only checkpoint every 1000 IDs in order to prevent unnecessary churn
				// in the checkpoint file
				if checkpointFile != "" && numDeleted%1000 == 0 {
					err = saveCheckpoint(checkpointFile, id)
					if err != nil {
						p.log.AuditErrf("failed to checkpoint %q table at ID %q: %s", table, id, err)
					}
				}
			}
		}()
	}

	wg.Wait()
	p.log.Infof("Deleted a total of %d expired authorizations from %s", deleted, table)
}

// purge looks up pending or finalized authzs (depending on the value of
// `table`) that expire before `purgeBefore`, using `parallelism`
// goroutines. It will delete a maximum of `max` authzs if daemon is not true.
// Neither table has an index on `expires` by itself, so we just iterate through
// the table with LIMIT and OFFSET using the default ordering. Note that this
// becomes expensive once the earliest set of authzs has been purged, since the
// database will have to scan through many rows before it finds some that meet
// the expiration criteria. When we move to better authz storage (#2620), we
// will get an appropriate index that will make this cheaper.
//
// If daemon is true purge will run indefinitely looking for authorizations to
// purge. If getWork returns the same ID that was passed to it then it will
// sleep a minute before looking for more authorizations again, starting at the
// same ID.
//
// If maxDPS is set the number of DELETE statements from both the pendingAuthorizations
// and authz tables will be capped at the passed rate.
func (p *expiredAuthzPurger) purge(
	table string,
	purgeBefore time.Time,
	parallelism int,
	max int,
	daemon bool,
	checkpointFile string,
	maxDPS int,
) error {
	var query string
	switch table {
	case "pendingAuthorizations":
		query = "SELECT id FROM pendingAuthorizations WHERE id >= :id AND expires <= :expires ORDER BY id LIMIT :limit"
	case "authz":
		query = "SELECT id FROM authz WHERE id >= :id AND expires <= :expires ORDER BY id LIMIT :limit"
	}

	// id starts as "", which is smaller than all other ids.
	var id string
	if checkpointFile != "" {
		startID, err := loadCheckpoint(checkpointFile)
		if err != nil {
			return err
		}
		id = startID
	}

	work := make(chan string)
	go func() {
		var count int

		var working func() bool
		if daemon {
			working = func() bool { return true }
		} else {
			working = func() bool { return count < max }
		}

		for working() {
			lastID, added, err := p.getWork(work, query, id, purgeBefore, p.batchSize)
			if err != nil {
				p.log.AuditErr(err.Error())
				time.Sleep(time.Millisecond * 500)
				continue
			} else if daemon && lastID == id {
				time.Sleep(time.Minute)
			} else if !daemon && added < int(p.batchSize) {
				break
			}
			count += added
			id = lastID
		}
		close(work)
	}()

	p.deleteAuthorizations(work, maxDPS, parallelism, table, checkpointFile)

	return nil
}

func deleteAuthorization(db eapDB, table, id string) error {
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
	deletedStat.WithLabelValues(table).Inc()
	return nil
}

func main() {
	daemon := flag.Bool("daemon", false, "Runs the expired-authz-purger in daemon mode")
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

	var logger blog.Logger
	if config.ExpiredAuthzPurger.DebugAddr != "" {
		var scope metrics.Scope
		scope, logger = cmd.StatsAndLogging(config.ExpiredAuthzPurger.Syslog, config.ExpiredAuthzPurger.DebugAddr)
		scope.MustRegister(deletedStat)
	} else {
		logger = cmd.NewLogger(config.ExpiredAuthzPurger.Syslog)
	}
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

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

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := purger.purge(
			"authz",
			purgeBefore,
			int(config.ExpiredAuthzPurger.Parallelism),
			int(config.ExpiredAuthzPurger.MaxAuthzs),
			*daemon,
			config.ExpiredAuthzPurger.FinalCheckpointFile,
			config.ExpiredAuthzPurger.MaxDPS,
		)
		cmd.FailOnError(err, "Failed to purge authorizations")
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := purger.purge(
			"pendingAuthorizations",
			purgeBefore,
			int(config.ExpiredAuthzPurger.Parallelism),
			int(config.ExpiredAuthzPurger.MaxAuthzs),
			*daemon,
			config.ExpiredAuthzPurger.PendingCheckpointFile,
			config.ExpiredAuthzPurger.MaxDPS,
		)
		cmd.FailOnError(err, "Failed to purge authorizations")
	}()
	wg.Wait()
}
