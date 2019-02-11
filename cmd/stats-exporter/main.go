package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/letsencrypt/boulder/cmd"
)

func writeTSVData(rows *sql.Rows, outFile *os.File) {
	for rows.Next() {
		var (
			id, rname, notBefore, serial string
		)
		if err := rows.Scan(&id, &rname, &notBefore, &serial); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(outFile, "%s\t%s\t%s\t%s\n", id, rname, notBefore, serial)
	}
}
func main() {
	dbConnection := flag.String("dbConnection", "", "Path to the DB URL")
	scpLocation := flag.String("destination", "localhost:/tmp", "Location to SCP the TSV output to")
	flag.Parse()

	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)
	yesterdayDateStamp := yesterday.Format("2006-01-02")
	endDateStamp := now.Format("2006-01-02")
	outputFileName := fmt.Sprintf("results-%s.tsv", yesterday.Format("2006-01-02"))
	outputGZIPName := outputFileName + ".gz"

	dbDSN, err := ioutil.ReadFile(*dbConnection)
	cmd.FailOnError(err, "Could not open database connection file")

	db, err := sql.Open("mysql", strings.TrimSpace(string(dbDSN)))
	cmd.FailOnError(err, "Could not establish database connection")

	outFile, err := os.OpenFile(outputFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	cmd.FailOnError(err, "Could not write to results file")

	// this query needs to be fixed because it gets the 00:00:00 minute of the first and last date
	rows, err := db.Query(`SELECT id,reversedName,notBefore,serial FROM issuedNames where notBefore between ? and ?`, yesterdayDateStamp, endDateStamp)
	cmd.FailOnError(err, "Could not reach database and run query")

	defer rows.Close()
	writeTSVData(rows, outFile)

	outFile.Close()
	err = exec.Command("/usr/bin/gzip", outputFileName).Run()
	cmd.FailOnError(err, "Could not gzip file")

	err = exec.Command("/usr/bin/scp", outputGZIPName, *scpLocation).Run()
	cmd.FailOnError(err, "Could not SCP file")
}
