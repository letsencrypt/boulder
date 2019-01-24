package main

import (
	"database/sql"
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
	rows, err := db.Query(`SELECT reversedName FROM issuedNames`)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			rname string
		)
		if err := rows.Scan(&rname); err != nil {
			log.Fatal(err)
		}
		log.Printf("reversedName is %s\n", rname)
	}
	log.Println("Hello LE Team")
}
