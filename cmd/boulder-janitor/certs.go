package main

import (
	"github.com/jmhodges/clock"
	blog "github.com/letsencrypt/boulder/log"
)

// newCertificatesJob returns a batchedDBJob configured to delete expired rows
// from the certificates table.
func newCertificatesJob(
	db janitorDB,
	log blog.Logger,
	clk clock.Clock,
	config Config) *batchedDBJob {
	purgeBefore := config.Janitor.Certificates.GracePeriod.Duration
	workQuery := `
		 SELECT id, expires FROM certificates
		 WHERE
		   id > :startID
		 LIMIT :limit`
	log.Debugf("Creating Certificates job from config: %#v\n", config.Janitor.Certificates)
	return &batchedDBJob{
		db:          db,
		log:         log,
		clk:         clk,
		purgeBefore: purgeBefore,
		workSleep:   config.Janitor.Certificates.WorkSleep.Duration,
		batchSize:   config.Janitor.Certificates.BatchSize,
		maxDPS:      config.Janitor.Certificates.MaxDPS,
		parallelism: config.Janitor.Certificates.Parallelism,
		table:       "certificates",
		workQuery:   workQuery,
	}
}
