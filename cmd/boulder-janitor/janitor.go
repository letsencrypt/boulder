package main

import (
	"errors"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

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
	db   db.DatabaseMap
	jobs []*batchedDBJob
}

// New creates a janitor instance from the provided configuration or errors. The
// janitor will not be running until its Run() function is invoked.
func New(clk clock.Clock, config Config) (*janitor, error) {
	if err := config.Valid(); err != nil {
		return nil, err
	}

	// Enable configured feature flags
	if err := features.Set(config.Janitor.Features); err != nil {
		return nil, err
	}

	// Setup logging and stats
	scope, logger := cmd.StatsAndLogging(config.Janitor.Syslog, config.Janitor.DebugAddr)
	scope.MustRegister(errStat)
	scope.MustRegister(deletedStat)
	scope.MustRegister(workStat)
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
	dbMap db.DatabaseMap,
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
		// Since we rely on data in the certificatesPerName table to calculate
		// rate limits we don't want to delete anything that is still being
		// relied for those calculations. If we are asked to purge anything
		// less than 7 days old we return an error.
		if config.Janitor.CertificatesPerName.GracePeriod.Duration < time.Hour*24*7 {
			return nil, errors.New("certificatesPerName GracePeriod must be more than 7 days")
		}
		jobs = append(jobs, newCertificatesPerNameJob(dbMap, logger, clk, config))
	}
	if config.Janitor.KeyHashToSerial.Enabled {
		jobs = append(jobs, newKeyHashToSerialJob(dbMap, logger, clk, config))
	}
	if config.Janitor.Orders.Enabled {
		jobs = append(jobs, newOrdersJob(dbMap, logger, clk, config.Janitor.Orders))
	}
	// There must be at least one job
	if len(jobs) == 0 {
		return nil, errNoJobsConfigured
	}
	// The jobs must all be valid
	for _, j := range jobs {
		if err := j.valid(); err != nil {
			return nil, err
		}
		// if no explicit deleteHandler is specified use the default
		if j.deleteHandler == nil {
			j.deleteHandler = j.simpleResourceDelete
		}
	}
	return jobs, nil
}

// Run starts the janitor daemon. Each configured job will start running in
// dedicated go routines. The janitor will block on the completion of these
// jobs (presently forever).
func (j *janitor) Run() {
	waitChan := make(chan bool)
	// Run each job
	for _, job := range j.jobs {
		go job.RunForever()
	}
	// Wait forever
	<-waitChan
}
