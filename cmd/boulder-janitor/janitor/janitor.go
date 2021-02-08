package janitor

import (
	"errors"

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

// JanitorConfig is an exported type which can have json config values
// marshalled into it. It is the input to New(), below.
type JanitorConfig struct {
	// Syslog holds common syslog configuration.
	Syslog cmd.SyslogConfig
	// DebugAddr controls the bind address for prometheus metrics, etc.
	DebugAddr string
	// Features holds potential Feature flags.
	Features map[string]bool
	// Common database connection configuration.
	cmd.DBConfig

	// JobConfigs is a list of configs for individual cleanup jobs.
	JobConfigs []JobConfig
}

// Janitor is a struct for a long-running cleanup daemon tasked with multiple
// cleanup jobs.
type Janitor struct {
	log  blog.Logger
	clk  clock.Clock
	db   db.DatabaseMap
	jobs []*batchedDBJob
}

// New creates a janitor instance from the provided configuration or errors. The
// janitor will not be running until its Run() function is invoked.
func New(clk clock.Clock, config JanitorConfig) (*Janitor, error) {
	if config.DebugAddr == "" {
		return nil, errors.New("metricsAddr must not be empty")
	}

	// Enable configured feature flags
	if err := features.Set(config.Features); err != nil {
		return nil, err
	}

	// Setup logging and stats
	scope, logger := cmd.StatsAndLogging(config.Syslog, config.DebugAddr)
	scope.MustRegister(errStat)
	scope.MustRegister(deletedStat)
	scope.MustRegister(workStat)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	// Create DB Map
	dbURL, err := config.DBConfig.URL()
	if err != nil {
		return nil, err
	}
	dbSettings := sa.DbSettings{
		MaxOpenConns:    config.DBConfig.MaxOpenConns,
		MaxIdleConns:    config.DBConfig.MaxIdleConns,
		ConnMaxLifetime: config.DBConfig.ConnMaxLifetime.Duration,
		ConnMaxIdleTime: config.DBConfig.ConnMaxIdleTime.Duration,
	}
	dbMap, err := sa.NewDbMap(dbURL, dbSettings)
	if err != nil {
		return nil, err
	}
	sa.SetSQLDebug(dbMap, logger)

	// Construct configured jobs
	jobs, err := newJobs(config.JobConfigs, dbMap, logger, clk)
	if err != nil {
		return nil, err
	}

	return &Janitor{
		log:  logger,
		clk:  clk,
		db:   dbMap,
		jobs: jobs,
	}, nil
}

// newJobs constructs a list of batchedDBJobs based on the provided config. If
// no jobs are enabled in the config then errNoJobsConfigured is returned.
func newJobs(configs []JobConfig, dbMap db.DatabaseMap, logger blog.Logger, clk clock.Clock) ([]*batchedDBJob, error) {
	var jobs []*batchedDBJob
	for _, c := range configs {
		j := newJob(c, dbMap, logger, clk)
		if j != nil {
			jobs = append(jobs, j)
		}
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
	}
	return jobs, nil
}

// Run starts the janitor daemon. Each configured job will start running in
// dedicated go routines. The janitor will block on the completion of these
// jobs (presently forever).
func (j *Janitor) Run() {
	waitChan := make(chan bool)
	// Run each job
	for _, job := range j.jobs {
		go job.runForever()
	}
	// Wait forever
	<-waitChan
}
