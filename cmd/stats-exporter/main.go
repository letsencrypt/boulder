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
)

func main() {
	dbConnection := flag.String("dbConnection", "issued_names_exporter_dburl", "Path to the DB URL")
	scpLocation := flag.String("destination", "localhost:/tmp", "Location to SCP the TSV output to")
	flag.Parse()

	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)
	yesterdayDateStamp := yesterday.Format("2006-01-02")
	endDateStamp := now.Format("2006-01-02")
	outputFileName := fmt.Sprintf("results-%s.tsv", yesterday.Format("2006-01-02"))
	outputGZIPName := outputFileName + ".gz"

	dbDSN, err := ioutil.ReadFile(*dbConnection)
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("mysql", strings.TrimSpace(string(dbDSN)))
	if err != nil {
		log.Fatal(err)
	}
	outFile, err := os.OpenFile(outputFileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal(err)
	}
	rows, err := db.Query(`SELECT id,reversedName,notBefore,serial FROM issuedNames where notBefore between ? and ?`, yesterdayDateStamp, endDateStamp)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id, rname, notBefore, serial string
		)
		if err := rows.Scan(&id, &rname, &notBefore, &serial); err != nil {
			log.Fatal(err)
		}
		fmt.Fprintf(outFile, "%s\t%s\t%s\t%s\n", id, rname, notBefore, serial)
	}
	outFile.Close()
	err = exec.Command("/usr/bin/gzip", outputFileName).Run()
	if err != nil {
		log.Fatal(err)
	}
	err = exec.Command("/usr/bin/scp", outputGZIPName, *scpLocation).Run()
	if err != nil {
		log.Fatal(err)
	}
}
