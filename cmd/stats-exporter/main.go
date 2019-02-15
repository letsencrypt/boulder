package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/cmd"
)

type sqlRows interface {
	Next() bool
	Scan(dest ...interface{}) error
}

type dbQueryable interface {
	Query(string, ...interface{}) (*sql.Rows, error)
}

var sqlOpen = func(driver, dsn string) (dbQueryable, error) {
	return sql.Open(driver, dsn)
}

var execRun = func(c *exec.Cmd) error {
	return c.Run()
}

func queryDB(dbConnect, beginTimeStamp, endTimeStamp string) (*sql.Rows, error) {
	dbDSN, err := ioutil.ReadFile(dbConnect)
	if err != nil {
		return nil, fmt.Errorf("Could not open database connection file: %s", err)
	}
	db, err := sqlOpen("mysql", strings.TrimSpace(string(dbDSN)))
	if err != nil {
		return nil, fmt.Errorf("Could not establish database connection: %s", err)
	}
	rows, err := db.Query(`SELECT id,reversedName,notBefore,serial FROM issuedNames where notBefore >= ? and notBefore < ?`, beginTimeStamp, endTimeStamp)
	if err != nil {
		return nil, fmt.Errorf("Could not reach database and run query: %s", err)
	}
	return rows, nil
}

func writeTSVData(rows sqlRows, outFile io.Writer) error {
	for rows.Next() {
		var (
			id, rname, notBefore, serial string
		)
		if err := rows.Scan(&id, &rname, &notBefore, &serial); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(outFile, "%s\t%s\t%s\t%s\n", id, rname, notBefore, serial); err != nil {
			return err
		}
	}
	return nil
}

func compress(outputFileName string) error {
	gzipCmd := exec.Command("/usr/bin/gzip", outputFileName)
	err := execRun(gzipCmd)
	if err != nil {
		return fmt.Errorf("Could not gzip result file: %s", err)
	}
	return nil
}

func scp(outputFileName, destination, key string) error {
	outputGZIPName := outputFileName + ".gz"
	scpCmd := exec.Command("/usr/bin/scp", "-i", key, outputGZIPName, destination)
	err := execRun(scpCmd)
	if err != nil {
		return fmt.Errorf("Could not scp result file: %s", err)
	}
	return nil
}
func main() {
	dbConnect := flag.String("dbConnect", "", "Path to the DB URL")
	destination := flag.String("destination", "localhost:/tmp", "Location to SCP the TSV result file to")
	key := flag.String("key", "id_rsa", "Identity key for SCP")
	flag.Parse()

	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)
	yesterdayDateStamp := yesterday.Format("2006-01-02")
	endDateStamp := now.Format("2006-01-02")
	outputFileName := fmt.Sprintf("results-%s.tsv", yesterday.Format("2006-01-02"))

	outFile, err := os.OpenFile(outputFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	cmd.FailOnError(err, "Could not create results file")

	defer func() {
		if err := outFile.Close(); err != nil {
			cmd.FailOnError(err, "Could not close file")
		}
	}()

	rows, err := queryDB(*dbConnect, yesterdayDateStamp, endDateStamp)
	cmd.FailOnError(err, "Could not complete database work")

	err = writeTSVData(rows, outFile)
	cmd.FailOnError(err, "Could not write TSV data")

	err = compress(outputFileName)
	cmd.FailOnError(err, "Could not compress results")
	err = scp(outputFileName, *destination, *key)
	cmd.FailOnError(err, "Could not send results")
}
