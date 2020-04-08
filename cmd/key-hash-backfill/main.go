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
		(keyHash, certExpires, certSerial)
		VALUES (?, ?, ?)`,
		keyHash,
		expires,
		serial,
	)
	return err
}

type workUnit struct {
	Serial  string
	DER     []byte
	Expires time.Time
}

var batchSize = 1000

func getWork(logger log.Logger, dbMap *db.WrappedMap) ([]workUnit, error) {
	var data []workUnit
	// Get rows that are in certificates but not in keyHashToSerial,
	// this should trend towards 0
	_, err := dbMap.Select(
		&data,
		`SELECT a.serial, a.der, a.expires
		FROM certificates AS a
		LEFT JOIN keyHashToSerial AS b
		ON a.serial = b.certSerial
		WHERE b.certSerial IS NULL
		LIMIT ?`,
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
			return fmt.Errorf("failed to insert into keyHasToSerial: %s", err)
		}
	}
	return nil
}

func backfill(logger log.Logger, dbMap *db.WrappedMap) {
	for {
		work, err := getWork(logger, dbMap)
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

	backfill(logger, dbMap)
}
