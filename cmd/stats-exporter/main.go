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

func queryDB(dbConnect string, beginTimeStamp string, endTimeStamp string) (*sql.Rows, error) {
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
func main() {
	dbConnect := flag.String("dbConnect", "", "Path to the DB URL")
	destination := flag.String("destination", "localhost:/tmp", "Location to SCP the TSV result file to")
	flag.Parse()

	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)
	yesterdayDateStamp := yesterday.Format("2006-01-02")
	endDateStamp := now.Format("2006-01-02")
	outputFileName := fmt.Sprintf("results-%s.tsv", yesterday.Format("2006-01-02"))
	outputGZIPName := outputFileName + ".gz"

	outFile, err := os.OpenFile(outputFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	cmd.FailOnError(err, "Could not write to results file")
	defer outFile.Close()
	rows, err := queryDB(*dbConnect, yesterdayDateStamp, endDateStamp)
	cmd.FailOnError(err, "Could not complete database work")

	err = writeTSVData(rows, outFile)
	cmd.FailOnError(err, "Could not write TSV data")

	err = exec.Command("/usr/bin/gzip", outputFileName).Run()
	cmd.FailOnError(err, "Could not gzip file")

	err = exec.Command("/usr/bin/scp", outputGZIPName, *destination).Run()
	cmd.FailOnError(err, "Could not SCP file")
}
