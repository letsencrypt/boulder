package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
)

type dbAccess interface {
	SelectOne(holder interface{}, query string, args ...interface{}) error
	Select(holder interface{}, query string, args ...interface{}) ([]interface{}, error)
	Exec(query string, args ...interface{}) (sql.Result, error)
}

type backfiller struct {
	dbMap      dbAccess
	log        blog.Logger
	clk        clock.Clock
	dryRun     bool
	batchSize  uint
	numBatches uint
	sleep      time.Duration
}

func (b backfiller) printStatus(
	serial string, notAfter time.Time, cur, total int, start time.Time) {
	// Should never happen
	if total <= 0 || cur < 0 || cur > total {
		b.log.AuditErr(fmt.Sprintf(
			"invalid cur (%d) or total (%d)\n", cur, total))
	}
	completion := (float32(cur) / float32(total)) * 100
	now := b.clk.Now()
	elapsed := now.Sub(start)
	b.log.Info(
		fmt.Sprintf("Updating %q notAfter to %q. Cert. %d of %d [%.2f%%]. Elapsed: %s",
			serial, notAfter, cur+1, total, completion, elapsed.String()))
}

func (b backfiller) backfill(certStatus *core.CertificateStatus) error {
	// We explicit use `Exec` over `Update` to avoid contention on the
	// `LockCol` field that Gorp uses for optimistic locking. With an
	// `ocsp-updater` running at the same time as a backfill there is a pretty
	// good chance they would clobber each others `LockCol` values if we used
	// `Update()` instead of a raw `Exec()`.
	_, err := b.dbMap.Exec(
		`UPDATE certificateStatus
		 SET notAfter=?
		 WHERE serial=?`,
		certStatus.NotAfter,
		certStatus.Serial,
	)
	if err != nil {
		return err
	}
	return nil
}

func (b backfiller) findEmpty() ([]*core.CertificateStatus, error) {
	var certs []*core.CertificateStatus

	_, err := b.dbMap.Select(&certs,
		`SELECT
			 serial
			 FROM certificateStatus
			 WHERE notAfter IS NULL
			 LIMIT :batchSize`,
		map[string]interface{}{
			"batchSize": b.batchSize,
		},
	)
	if err != nil {
		return certs, err
	}

	return certs, nil
}

func (b backfiller) populateNotAfter(certs []*core.CertificateStatus) error {
	for _, cs := range certs {
		var c core.Certificate

		err := b.dbMap.SelectOne(&c,
			`SELECT expires
			FROM certificates
			WHERE serial = :serial`,
			map[string]interface{}{
				"serial": cs.Serial,
			})
		if err != nil {
			return err
		}
		cs.NotAfter = c.Expires
	}
	return nil
}

func (b backfiller) processBatch() (int, error) {
	certs, err := b.findEmpty()
	if err != nil {
		return 0, err
	}

	b.log.Info(fmt.Sprintf("Found %d certificates for this batch", len(certs)))
	if len(certs) == 0 {
		return 0, nil // Nothing to backfill!
	}

	err = b.populateNotAfter(certs)
	if err != nil {
		return 0, err
	}

	startTime := b.clk.Now()
	for i, c := range certs {
		b.printStatus(c.Serial, c.NotAfter, i, len(certs), startTime)
		if !b.dryRun {
			err := b.backfill(c)
			if err != nil {
				return i, err
			}
		}
	}
	return len(certs), nil
}

func (b backfiller) processForever() error {
	var batchNum uint
	for {
		start := b.clk.Now()
		b.log.Info(fmt.Sprintf("Starting to process batch %d", batchNum+1))
		processed, err := b.processBatch()
		now := b.clk.Now()
		elapsed := now.Sub(start)
		if err != nil {
			return err
		}
		b.log.Info(fmt.Sprintf("Batch %d finished. Processed %d certificates in %s",
			batchNum+1, processed, elapsed))
		if processed == 0 {
			b.log.Info("No more certificates to process. Terminating.")
			break
		}
		batchNum++
		if batchNum >= b.numBatches {
			b.log.Info(fmt.Sprintf("Reached numBatches (%d). Terminating.", b.numBatches))
			break
		}
		b.log.Info(fmt.Sprintf("Sleeping for %s before next batch", b.sleep))
		b.clk.Sleep(b.sleep)
	}
	return nil
}

const usageIntro = `
Introduction:

The "20160817143417_AddCertStatusNotAfter.sql" db migration adds a "notAfter"
column to the certificateStatus database table. This field duplicates the
contents of the certificates table "expires" column. This enables performance
improvements[0] for both the ocsp-updater and the expiration-mailer utilities.  

Since existing rows will have a NULL value in the new field he notafter-backfill
utility exists to perform a one-time update of the existing certificateStatus
rows to set their notAfter column based on the data that exists in the
certificates table.

[0] https://github.com/letsencrypt/boulder/issues/1864

Examples:

  Process 50 certificates at a time, printing the updates but not performing
  them:

  notafter-backfill -config test/config/notafter-backfiller.json -batchSize=50
    -dryRun=true

  Process 1000 certificates at a time, quitting after 5 batches (5000
  certificates) and sleeping 10 minutes between batches:

  notafter-backfill -config test/config/notafter-backfiller.json -batchSize=1000
    -numBatches=5 -sleep=5m -dryRun=false

Required arguments:

- config

`

func main() {
	dryRun := flag.Bool("dryRun", true, "Whether to do a dry run.")
	sleep := flag.Duration("sleep", 60*time.Second, "How long to sleep between batches.")
	batchSize := flag.Uint("batchSize", 1000, "Number of certificates to process between sleeps.")
	numBatches := flag.Uint("numBatches", 999999, "Stop processing after N batches.")
	type config struct {
		NotAfterBackFiller struct {
			cmd.DBConfig
		}
		Statsd cmd.StatsdConfig
		Syslog cmd.SyslogConfig
	}
	configFile := flag.String("config", "", "File containing a JSON config.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n\n", usageIntro)
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	configData, err := ioutil.ReadFile(*configFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %q", *configFile))
	var cfg config
	err = json.Unmarshal(configData, &cfg)
	cmd.FailOnError(err, "Unmarshaling config")

	stats, log := cmd.StatsAndLogging(cfg.Statsd, cfg.Syslog)
	defer log.AuditPanic()

	dbURL, err := cfg.NotAfterBackFiller.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, 10)
	cmd.FailOnError(err, "Could not connect to database")
	go sa.ReportDbConnCount(dbMap, metrics.NewStatsdScope(stats, "NotAfterBackfiller"))

	b := backfiller{
		dbMap:      dbMap,
		log:        log,
		clk:        cmd.Clock(),
		dryRun:     *dryRun,
		batchSize:  *batchSize,
		numBatches: *numBatches,
		sleep:      *sleep,
	}

	err = b.processForever()
	cmd.FailOnError(err, "Could not process certificate batches")
}
