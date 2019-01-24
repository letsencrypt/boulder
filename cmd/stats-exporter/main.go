package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	now := time.Now()
	yesterday := now.Add(-24 * time.Hour)
	yesterdayDateStamp := yesterday.Format("2006-01-02")
	endDateStamp := now.Format("2006-01-02")
	outputFileName := fmt.Sprintf("results-%s.tsv", yesterday.Format("2006-01-02"))

	dbDSN, err := ioutil.ReadFile(os.Args[1])
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
}
