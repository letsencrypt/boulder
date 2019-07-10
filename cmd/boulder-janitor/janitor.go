package main

import (
	"database/sql"
	"errors"
	"sync"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
)

// janitorDB is an interface describing the two functions of a sql.DB that the
// janitor uses. It allows easy mocking of the DB for unit tests.
type janitorDB interface {
	Exec(query string, args ...interface{}) (sql.Result, error)
	Select(i interface{}, query string, args ...interface{}) ([]interface{}, error)
}

var (
	// errNoJobsConfigured is returned from New() when there are no jobs enabled
	// in the provided Config.
	errNoJobsConfigured = errors.New("no jobs enabled in configuration")
)

// janitor is a struct for a long-running cleanup daemon tasked with multiple
// cleanup jobs.
type janitor struct {
	log  blog.Logger
	clk  clock.Clock
	db   janitorDB
	jobs []*batchedDBJob
}

// New creates a janitor instance from the provided configuration or errors. The
// janitor will not be running until its Run() function is invoked.
func New(clk clock.Clock, config Config) (*janitor, error) {
	if err := config.Valid(); err != nil {
		return nil, err
	}

	// Setup logging and stats
	var logger blog.Logger
	if config.Janitor.DebugAddr != "" {
		var scope metrics.Scope
		scope, logger = cmd.StatsAndLogging(config.Janitor.Syslog, config.Janitor.DebugAddr)
		scope.MustRegister(deletedStat)
	} else {
		logger = cmd.NewLogger(config.Janitor.Syslog)
	}
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	// Create DB Map
	dbURL, err := config.Janitor.DBConfig.URL()
	if err != nil {
		return nil, err
	}
	dbMap, err := sa.NewDbMap(dbURL, config.Janitor.DBConfig.MaxDBConns)
	if err != nil {
		return nil, err
	}
	sa.SetSQLDebug(dbMap, logger)

	// Enable configured feature flags
	err = features.Set(config.Janitor.Features)
	if err != nil {
		return nil, err
	}

	// Construct configured jobs
	jobs, err := newJobs(dbMap, logger, clk, config)
	if err != nil {
		return nil, err
	}

	return &janitor{
		log:  logger,
		clk:  clk,
		db:   dbMap,
		jobs: jobs,
	}, nil
}

// newJobs constructs a list of batchedDBJobs based on the provided config. If
// no jobs are enabled in the config then errNoJobsConfigured is returned.
func newJobs(
	dbMap janitorDB,
	logger blog.Logger,
	clk clock.Clock,
	config Config) ([]*batchedDBJob, error) {
	var jobs []*batchedDBJob
	if config.Janitor.CertificateStatus.Enabled {
		jobs = append(jobs, newCertificateStatusJob(dbMap, logger, clk, config))
	}
	if config.Janitor.Certificates.Enabled {
		jobs = append(jobs, newCertificatesJob(dbMap, logger, clk, config))
	}
	if config.Janitor.CertificatesPerName.Enabled {
		jobs = append(jobs, newCertificatesPerNameJob(dbMap, logger, clk, config))
	}
	if len(jobs) == 0 {
		return nil, errNoJobsConfigured
	}
	return jobs, nil
}

// Run starts the janitor daemon. Each configured job will start running in
// dedicated go routines. The janitor will block on the completion of these
// jobs (presently forever).
func (j *janitor) Run() error {
	// Run each job and wait for all of them to complete
	wg := new(sync.WaitGroup)
	for _, job := range j.jobs {
		wg.Add(1)
		go job.RunForever()
	}
	wg.Wait()
	return nil
}
