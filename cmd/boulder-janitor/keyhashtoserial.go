package main

import (
	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
)

// newKeyHashToSerialJob returns a batchedDBJob configured to delete expired
// rows from the keyHashToSerial table.
func newKeyHashToSerialJob(
	dbMap db.DatabaseMap,
	log blog.Logger,
	clk clock.Clock,
	config Config) *batchedDBJob {
	purgeBefore := config.Janitor.KeyHashToSerial.GracePeriod.Duration
	workQuery := `SELECT id, certNotAfter AS expires FROM keyHashToSerial
		 WHERE
		   id > :startID
		 LIMIT :limit`
	log.Debugf("Creating KeyHashToSerial job from config: %#v", config.Janitor.KeyHashToSerial)
	return &batchedDBJob{
		db:          dbMap,
		log:         log,
		clk:         clk,
		purgeBefore: purgeBefore,
		workSleep:   config.Janitor.KeyHashToSerial.WorkSleep.Duration,
		batchSize:   config.Janitor.KeyHashToSerial.BatchSize,
		maxDPS:      config.Janitor.KeyHashToSerial.MaxDPS,
		parallelism: config.Janitor.KeyHashToSerial.Parallelism,
		table:       "keyHashToSerial",
		workQuery:   workQuery,
	}
}
