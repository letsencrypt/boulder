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
	purgeBefore := clk.Now().Add(-config.Janitor.Certificates.GracePeriod.Duration)
	workQuery := `
		 SELECT id FROM certificates
		 WHERE
		   id > :startID AND
		   expires <= :cutoff
		 ORDER by id
		 LIMIT :limit`
	return &batchedDBJob{
		db:          db,
		log:         log,
		purgeBefore: purgeBefore,
		batchSize:   config.Janitor.Certificates.BatchSize,
		maxDPS:      config.Janitor.Certificates.MaxDPS,
		parallelism: config.Janitor.Certificates.Parallelism,
		table:       "certificates",
		workQuery:   workQuery,
	}
}
