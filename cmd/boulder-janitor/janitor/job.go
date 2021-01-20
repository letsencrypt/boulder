package janitor

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// minPurgeBefore is the smallest purgeBefore time.Duration that can be
	// configured for a job. We set this to 90 days to match the default validity
	// window of Let's Encrypt certificates.
	minPurgeBefore = time.Hour * 24 * 90
)

var (
	// errStat is a prometheus counter vector tracking the number of errors
	// experienced by the janitor during operation sliced by a table label and a
	// type label. Examples of possible type labels include "getWork" and
	// "deleteResource".
	errStat = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "janitor_errors",
			Help: "Number of errors by type the boulder-janitor has experienced.",
		},
		[]string{"table", "type"})
	// deletedStat is a prometheus counter vector tracking the number of rows
	// deleted by the janitor, sliced by a table label.
	deletedStat = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "janitor_deletions",
			Help: "Number of deletions by table the boulder-janitor has performed.",
		},
		[]string{"table"})
	// workStat is a prometheus counter vector tracking the number of rows found
	// during a batchedJob's getWork stage and queued into the work channel sliced
	// by a table label.
	workStat = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "janitor_workbatch",
			Help: "Number of items of work by table the boulder-janitor queued for deletion.",
		},
		[]string{"table"})
)

// JobConfig describes common configuration parameters shared by all cleanup
// jobs.
type JobConfig struct {
	// Enabled controls whether the janitor will run this cleanup job.
	Enabled bool
	// Table is the name of the table which this job will clean up.
	Table string
	// ExpiresColumn is the name of the column in `Table` containing expiration datetimes.
	ExpiresColumn string
	// GracePeriod controls when a resource is old enough to be cleaned up.
	GracePeriod cmd.ConfigDuration
	// WorkSleep controls how long the janitor's work threads sleep between
	// finding no work and trying again. Defaults to a minute if not provided.
	WorkSleep cmd.ConfigDuration
	// BatchSize controls how many rows of the resource will be read from the DB
	// per-query.
	BatchSize int64
	// Parallelism controls how many independent go routines will run Delete
	// statements for old resources being cleaned up.
	Parallelism int
	// MaxDPS controls the maximum number of deletes which will be performed
	// per second in total for the resource's table across all of the parallel go
	// routines for this resource. This can be used to reduce the replication lag
	// caused by creating a very large numbers of delete statements.
	MaxDPS int
	// DeleteHandler is the string name of a function (found in handlers.go) to
	// use to handle deletion of rows.
	DeleteHandler string
}

// batchedDBJob is a struct abstracting the common properties of a long running
// cleanup job based on cursoring across a database table's auto incrementing
// primary key.
type batchedDBJob struct {
	db  db.DatabaseMap
	log blog.Logger
	clk clock.Clock
	// table is the name of the table that this job cleans up.
	table string
	// expiresColumn is the name of the column in `table` containing expiration datetimes.
	expiresColumn string
	// purgeBefore indicates the cut-off for the the resource being cleaned up by
	// the job. Rows that older than now - purgeBefore are deleted.
	purgeBefore time.Duration
	// workSleep is a duration that the job will sleep between getWork() calls
	// when no new work is found. If not provided, defaults to a minute.
	workSleep time.Duration
	// batchSize indicates how many database rows of work should be returned per query.
	batchSize int64
	// maxDPS optionally indicates a maximum rate of deletes to run per second.
	maxDPS int
	// parallelism controls how many independent go routines will be performing
	// cleanup deletes.
	parallelism int
	// deleteHandler is a function which will be called to handle deletions of
	// rows. The function must take a single int64 (the unique ID of the row to
	// be deleted) and return an error if deletion was unsuccessful. By default,
	// this should simply delete the single row in with the given ID in `table`.
	// More complex deletion logic may be necessary e.g. if there are other
	// tables with foreign keys which reference the given row.
	deleteHandler func(job *batchedDBJob, id int64) error
}

func newJob(config JobConfig, dbMap db.DatabaseMap, log blog.Logger, clk clock.Clock) *batchedDBJob {
	if !config.Enabled {
		return nil
	}
	log.Debugf("Creating job from config: %#v", config)

	expires := "expires"
	if config.ExpiresColumn != "" {
		expires = config.ExpiresColumn
	}

	delete, ok := deleteHandlers[config.DeleteHandler]
	if !ok {
		delete = deleteDefault
	}

	return &batchedDBJob{
		db:            dbMap,
		log:           log,
		clk:           clk,
		table:         config.Table,
		expiresColumn: expires,
		purgeBefore:   config.GracePeriod.Duration,
		workSleep:     config.WorkSleep.Duration,
		batchSize:     config.BatchSize,
		maxDPS:        config.MaxDPS,
		parallelism:   config.Parallelism,
		deleteHandler: delete,
	}
}

var (
	errNoTable       = errors.New("table must not be empty")
	errNoPurgeBefore = fmt.Errorf("purgeBefore must be greater than %s", minPurgeBefore)
	errNoBatchSize   = errors.New("batchSize must be > 0")
	errNoParallelism = errors.New("parallelism must be > 0")
)

// valid checks that the batchedDBJob has all required fields set correctly and
// returns an error if not satisfied.
func (j *batchedDBJob) valid() error {
	if j.table == "" {
		return errNoTable
	}
	if j.purgeBefore <= minPurgeBefore {
		return errNoPurgeBefore
	}
	if j.batchSize <= 0 {
		return errNoBatchSize
	}
	if j.parallelism <= 0 {
		return errNoParallelism
	}
	// One strange special-case: Because certificatesPerName doesn't have a real
	// `expires` column, we use the grace period of 7 days to ensure that it
	// doesn't delete any rows that are still being used.
	if j.table == "certificatesPerName" && j.purgeBefore < time.Hour*24*7 {
		return errors.New("certificatesPerName GracePeriod must be more than 7 days")
	}
	return nil
}

type workUnit struct {
	ID      int64
	Expires time.Time
}

// getWork reads work into the provided work channel starting at the startID by
// using the batchedDBJob's configured work query, purgeBefore, and batchSize.
// If there is no error the last primary key ID written to the work channel will
// be returned, otherwise an error result is returned.
func (j batchedDBJob) getWork(work chan<- int64, startID int64) (int64, error) {
	var data []workUnit
	// This SQL query is used to find more work. It will be provided two parameters:
	//   * :startID       - the primary key value to start the work query from.
	//   * :limit         - the maximum number of rows to be returned by the query.
	// It will always return results with two columns:
	//   * id      - the primary key value for each row.
	//   * expires - the expiry datetime used to calculate if the row is within the cutoff window.
	// Unfortunately, we have to interpolate the expires column name and the
	// table name ourselves, because you can't parameterize those fields in
	// prepared statements.
	workQuery := fmt.Sprintf(`
SELECT id, %s AS expires
FROM %s
WHERE id > :startID
LIMIT :limit`, j.expiresColumn, j.table)
	values := map[string]interface{}{
		"startID": startID,
		"limit":   j.batchSize,
	}
	_, err := j.db.Select(&data, workQuery, values)
	if err != nil && !db.IsNoRows(err) {
		return 0, err
	}
	lastID := startID
	rows := 0
	cutoff := j.clk.Now().Add(-j.purgeBefore)
	for _, v := range data {
		// We check for the expiration in code rather than doing so in the
		// database query as it allows us to impose a bound on the number
		// of rows that the database will examine. If a row is return that
		// has an expiry after the cutoff all of the successive rows
		// should also have an expiry after the cutoff so we break from
		// the loop and ignore the rest of the results.
		if v.Expires.After(cutoff) {
			break
		}
		work <- v.ID
		rows++
		lastID = v.ID
	}
	workStat.WithLabelValues(j.table).Add(float64(rows))
	return lastID, nil
}

// cleanResource uses the configured level of parallelism to run go routines
// that read ID values from the work channel and delete the corresponding table
// rows. If the batchedDBJob configures a maxDPS rate then it will be enforced by
// synchronizing the delete operations on a ticker based on the maxDPS.
// cleanResource will block until all of the worker go routines complete.
func (j batchedDBJob) cleanResource(work <-chan int64) {
	wg := new(sync.WaitGroup)
	deleted := int64(0)

	var ticker *time.Ticker
	if j.maxDPS > 0 {
		ticker = time.NewTicker(
			time.Duration(float64(time.Second) / float64(j.maxDPS)))
	}

	for i := 0; i < j.parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				if ticker != nil {
					<-ticker.C
				}
				if err := j.deleteHandler(&j, id); err != nil {
					j.log.Errf(
						"error deleting ID %d from table %q: %s",
						id, j.table, err)
					errStat.WithLabelValues(j.table, "deleteResource").Inc()
				}
				_ = atomic.AddInt64(&deleted, 1)
			}
		}()
	}

	wg.Wait()
	j.log.Infof(
		"deleted a total of %d rows from table %q",
		deleted, j.table)
}

// RunForever starts a go routine that will run forever getting work with
// getWork and deleting rows with cleanResource.
func (j batchedDBJob) runForever() {
	var id int64
	work := make(chan int64)

	go func() {
		for {
			lastID, err := j.getWork(work, id)
			if err != nil {
				j.log.Errf("error getting work for %q from ID %d: %s",
					j.table, id, err.Error())
				errStat.WithLabelValues(j.table, "getWork").Inc()
				time.Sleep(time.Millisecond * 500)
				continue
			} else if lastID == id {
				j.log.Debugf(
					"made no new progress on table %q. Sleeping for a minute",
					j.table)
				if j.workSleep.Seconds() == 0 {
					time.Sleep(time.Minute)
				} else {
					time.Sleep(j.workSleep)
				}
			}
			id = lastID
		}
	}()

	j.cleanResource(work)
}
