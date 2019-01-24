package main

import (
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	_ "github.com/go-sql-driver/mysql"
)

func main() {
	dbDSN, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("mysql", strings.TrimSpace(string(dbDSN)))
	if err != nil {
		log.Fatal(err)
	}
	outFile, err := os.OpenFile(os.Args[2], os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}
	rows, err := db.Query(`SELECT id,reversedName,notBefore,serial FROM issuedNames`)
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
