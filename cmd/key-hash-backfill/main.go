package main

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

func parseCert(certBytes []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return h[:], nil
}

func insertCert(dbMap *db.WrappedMap, keyHash []byte, expires time.Time, serial string) error {
	_, err := dbMap.Exec(
		`INSERT INTO keyHashToSerial
		(keyHash, certNotAfter, certSerial)
		VALUES (?, ?, ?)`,
		keyHash,
		expires,
		serial,
	)
	if db.IsDuplicate(err) {
		return nil
	}
	return err
}

type workUnit struct {
	ID      int
	Serial  string
	DER     []byte
	Expires time.Time
}

func getWork(logger log.Logger, dbMap *db.WrappedMap, batchSize int, initialID int) ([]workUnit, error) {
	var data []workUnit
	// Get rows that are in certificates but not in keyHashToSerial,
	// this should trend towards 0
	_, err := dbMap.Select(
		&data,
		`SELECT id, serial, der, expires
		FROM certificates
		WHERE id > ?
		ORDER BY id
		LIMIT ?`,
		initialID,
		batchSize,
	)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func doWork(logger log.Logger, dbMap *db.WrappedMap, work []workUnit) error {
	for _, unit := range work {
		h, err := parseCert(unit.DER)
		if err != nil {
			return fmt.Errorf("failed to parse certificate for %s: %s", unit.Serial, err)
		}
		err = insertCert(dbMap, h, unit.Expires, unit.Serial)
		if err != nil {
			return fmt.Errorf("failed to insert into keyHashToSerial: %s", err)
		}
	}
	return nil
}

func backfill(logger log.Logger, dbMap *db.WrappedMap, batchSize int, initialID int) {
	for {
		work, err := getWork(logger, dbMap, batchSize, initialID)
		if err != nil && err != sql.ErrNoRows {
			logger.Errf("failed to get certificates: %s", err)
			continue
		}
		if len(work) == 0 {
			break
		}
		if err := doWork(logger, dbMap, work); err != nil {
			logger.Errf("error while inserting key hashes: %s", err)
		}
		initialID = work[len(work)-1].ID
	}
}

func main() {
	var config struct {
		KeyHashBackfiller struct {
			cmd.DBConfig
		}
		Syslog cmd.SyslogConfig
	}
	configFile := flag.String("config", "", "File containing a JSON config.")
	initialID := flag.Int("initial-id", 0, "Initial certificate ID to start from")
	batchSize := flag.Int("batch-size", 1000, "Number of certificates to fetch per batch")
	flag.Parse()

	configBytes, err := ioutil.ReadFile(*configFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %q", *configFile))
	err = json.Unmarshal(configBytes, &config)
	cmd.FailOnError(err, "Unmarshaling config")

	logger := cmd.NewLogger(config.Syslog)
	defer logger.AuditPanic()

	dbURL, err := config.KeyHashBackfiller.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, config.KeyHashBackfiller.MaxDBConns)
	cmd.FailOnError(err, "Could not connect to database")

	backfill(logger, dbMap, *batchSize, *initialID)
}
