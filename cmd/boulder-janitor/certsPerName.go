package main

import (
	"github.com/jmhodges/clock"
	blog "github.com/letsencrypt/boulder/log"
)

// newCertificatesPerNameJob returns a batchedDBJob configured to delete expired
// rows from the certificatesPerName table.
func newCertificatesPerNameJob(
	db janitorDB,
	log blog.Logger,
	clk clock.Clock,
	config Config) *batchedDBJob {
	purgeBefore := config.Janitor.CertificatesPerName.GracePeriod.Duration
	// Technically the `time` column in certificatesPerName is not an expiry, it is
	// the time at which it was inserted into the table, but we use it as the cutoff
	// for deletions here as we only care about data in this table for 7 days after
	// it was inserted.
	workQuery := `SELECT id, time AS expires FROM certificatesPerName
		 WHERE
		   id > :startID
		 LIMIT :limit`
	log.Debugf("Creating CertificatesPerName job from config: %#v\n", config.Janitor.CertificatesPerName)
	return &batchedDBJob{
		db:          db,
		log:         log,
		clk:         clk,
		purgeBefore: purgeBefore,
		workSleep:   config.Janitor.CertificatesPerName.WorkSleep.Duration,
		batchSize:   config.Janitor.CertificatesPerName.BatchSize,
		maxDPS:      config.Janitor.CertificatesPerName.MaxDPS,
		parallelism: config.Janitor.CertificatesPerName.Parallelism,
		table:       "certificatesPerName",
		workQuery:   workQuery,
	}
}
