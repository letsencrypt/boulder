package main

import (
	"crypto/sha256"
	"crypto/x509"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
)

type resultHolder struct {
	Serial  string
	Issued  time.Time
	Expires time.Time
	DER     []byte
}

type backfiller struct {
	sa    core.StorageAuthority
	dbMap *gorp.DbMap
	stats statsd.Statter
	log   *blog.AuditLogger
	clk   clock.Clock
}

func new(amqpConf *cmd.AMQPConfig, syslogConf cmd.SyslogConfig, statsdURI, dbURI string) (*backfiller, error) {
	var stats statsd.Statter
	var err error
	stats, log := cmd.StatsAndLogging(cmd.StatsdConfig{Server: statsdURI, Prefix: "Boulder"}, syslogConf)
	sac, err := rpc.NewStorageAuthorityClient("nameset-backfiller", amqpConf, stats)
	if err != nil {
		return nil, err
	}
	dbMap, err := sa.NewDbMap(dbURI)
	if err != nil {
		return nil, err
	}
	return &backfiller{sac, dbMap, stats, log, clock.Default()}, nil
}

func (b *backfiller) run() error {
	added := 0
	for {
		results, err := b.findCerts()
		if err != nil {
			return err
		}
		if len(results) == 0 {
			break
		}
		err = b.processResults(results)
		if err != nil {
			return err
		}
		added += len(results)
	}
	b.log.Info(fmt.Sprintf("Added %d missing certificate name sets to the fqdnSets table", added))
	return nil
}

func (b *backfiller) findCerts() ([]resultHolder, error) {
	var allResults []resultHolder
	for {
		var results []resultHolder
		_, err := b.dbMap.Select(
			&results,
			`SELECT c.serial, c.issued, c.expires, c.der FROM certificates AS c
       LEFT JOIN fqdnSets AS ns ON c.serial=ns.serial
       WHERE ns.serial IS NULL
       ORDER BY c.issued DESC
       LIMIT ?
       OFFSET ?`,
			1000,
			len(allResults),
		)
		if err != nil {
			return nil, err
		}
		if len(results) == 0 {
			break
		}
		b.stats.Inc("db-backfill.fqdnSets.missing-found", int64(len(results)), 1.0)
		allResults = append(allResults, results...)
	}
	return allResults, nil
}

func hashNames(names []string) []byte {
	names = core.UniqueLowerNames(names)
	hash := sha256.Sum256([]byte(strings.Join(names, ",")))
	return hash[:]
}

func (b *backfiller) processResults(results []resultHolder) error {
	numResults := len(results)
	added := 0
	for _, r := range results {
		c, err := x509.ParseCertificate(r.DER)
		if err != nil {
			b.log.Err(fmt.Sprintf("Failed to parse certificate [serial: %s] retrieved from database: %s", r.Serial, err))
			continue
		}
		err = b.dbMap.Insert(&core.FQDNSet{
			SetHash: hashNames(c.DNSNames),
			Serial:  r.Serial,
			Issued:  r.Issued,
			Expires: r.Expires,
		})
		if err != nil {
			b.log.Err(fmt.Sprintf("Failed to add name set for %s to database: %s", r.Serial, err))
			continue
		}
		added++
		b.stats.Inc("db-backfill.fqdnSets.added", 1, 1.0)
	}
	if added < numResults {
		return fmt.Errorf("Didn't add all name sets, %d out of %d failed", numResults-added, numResults)
	}
	return nil
}

func main() {
	amqpURI := flag.String("amqpURI", "", "AMQP connection URI")
	amqpURIFile := flag.String("amqpURIFile", "", "File to read AMQP connection URI from")
	amqpCert := flag.String("amqpCert", "", "AMQP client certificate to use")
	amqpKey := flag.String("amqpKey", "", "Key for AMQP client certificate")
	amqpCA := flag.String("amqpCA", "", "Root CA to trust for AMQP connections")

	statsdURI := flag.String("statsdURI", "", "StatsD URI")

	dbConnect := flag.String("dbConnect", "", "DB connection URI")
	dbConnectFile := flag.String("dbConnectFile", "", "File to read DB connection URI from")

	syslogNet := flag.String("syslogNetwork", "", "Syslog network")
	syslogURI := flag.String("syslogServer", "", "Syslog URI")
	syslogLevel := flag.Int("syslogLevel", 7, "Level at which to log")
	flag.Parse()

	dbConf := cmd.DBConfig{DBConnect: *dbConnect, DBConnectFile: *dbConnectFile}
	dbURI, err := dbConf.URL()

	amqpConf := &cmd.AMQPConfig{
		Server:        *amqpURI,
		ServerURLFile: *amqpURIFile,
		SA: &cmd.RPCServerConfig{
			Server:     "SA.server",
			RPCTimeout: cmd.ConfigDuration{Duration: time.Second * 15},
		},
	}
	if *amqpCert != "" && *amqpKey != "" && *amqpCA != "" {
		amqpConf.TLS = &cmd.TLSConfig{CertFile: amqpCert, KeyFile: amqpKey, CACertFile: amqpCA}
	} else {
		amqpConf.Insecure = true
	}
	cmd.FailOnError(err, "Failed to read db URI")
	b, err := new(
		amqpConf,
		cmd.SyslogConfig{
			Network:     *syslogNet,
			Server:      *syslogURI,
			StdoutLevel: syslogLevel,
		},
		*statsdURI,
		dbURI,
	)
	cmd.FailOnError(err, "Failed to create backfiller")
	err = b.run()
	cmd.FailOnError(err, "Failed to backfill fqdnSets table")
}
