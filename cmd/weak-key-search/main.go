package main

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/letsencrypt/boulder/goodkey"
)

func main() {
	sqlURI := flag.String("db", "", "")
	parallelism := flag.Int("parallelism", 1, "")
	weakKeyPath := flag.String("weak-keys", "", "")
	flag.Parse()

	wkl, err := goodkey.LoadWeakRSASuffixes(*weakKeyPath)
	if err != nil {
		panic(err)
	}

	db, err := sql.Open("mysql", *sqlURI)
	if err != nil {
		panic(err)
	}

	type certInfo struct {
		serial string
		der    []byte
	}
	var certs []certInfo

	query := "SELECT serial, der FROM certificates WHERE expires > ? LIMIT 1000 OFFSET ?"
	now := time.Now()

	for {
		rows, err := db.Query(query, now, len(certs))
		if err != nil && err != sql.ErrNoRows {
			panic(err)
		} else if err == sql.ErrNoRows {
			break
		}
		defer rows.Close()
		i := 0
		for rows.Next() {
			i++
			var c certInfo
			if err := rows.Scan(&c.serial, &c.der); err != nil {
				panic(err)
			}
			certs = append(certs, c)
		}
		if i == 0 {
			break
		}
	}

	work := make(chan certInfo, len(certs))
	for _, c := range certs {
		work <- c
	}

	wg := sync.WaitGroup{}
	for i := 0; i < *parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ci := range work {
				cert, err := x509.ParseCertificate(ci.der)
				if err != nil {
					panic(err)
				}
				if rk := cert.PublicKey.(*rsa.PublicKey); wkl.Known(rk) {
					fmt.Println("weak:", ci.serial)
				}
			}
		}()
	}
	wg.Wait()
}
