package main

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/goodkey"
	blog "github.com/letsencrypt/boulder/log"
)

type certInfo struct {
	serial string
	der    []byte
}

var limit = 1000

func getCerts(work chan certInfo, moreThan, lessThan time.Time, db *sql.DB) {
	query := "SELECT serial, der FROM certificates WHERE issued >= ? and issued < ? ORDER BY issued LIMIT ? OFFSET ?"
	i := 0
	for {
		rows, err := db.Query(query, moreThan, lessThan, limit, i)
		if err != nil && err != sql.ErrNoRows {
			cmd.FailOnError(err, "db.Query failed")
		} else if err == sql.ErrNoRows {
			break
		}
		defer func() { _ = rows.Close() }()
		prev := i
		for rows.Next() {
			i++
			var c certInfo
			if err := rows.Scan(&c.serial, &c.der); err != nil {
				cmd.FailOnError(err, "rows.Scan failed")
			}
			work <- c
		}
		if i == prev {
			break
		}
	}
	close(work)
}

func doWork(work chan certInfo, parallelism int, wkl *goodkey.WeakRSAKeys, log blog.Logger) {
	wg := sync.WaitGroup{}
	for i := 0; i < parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ci := range work {
				cert, err := x509.ParseCertificate(ci.der)
				cmd.FailOnError(err, "x509.ParseCertificate failed")
				if rk := cert.PublicKey.(*rsa.PublicKey); wkl.Known(rk) {
					log.Info(fmt.Sprintf("cert contains weak key: %s", ci.serial))
				}
			}
		}()
	}
	wg.Wait()
}

type config struct {
	cmd.SyslogConfig
	cmd.DBConfig
	WeakKeyFile    string
	Parallelism    int
	IssuedMoreThan string
	IssuedLessThan string
}

func main() {
	configFile := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Failed to read and parse configuration file")

	if c.Parallelism == 0 {
		log.Fatal("parallelism must be > 0")
	}

	_, log := cmd.StatsAndLogging(c.SyslogConfig)

	moreThan, err := time.Parse(time.RFC3339, c.IssuedMoreThan)
	cmd.FailOnError(err, "failed to parse issuedMoreThan")
	lessThan, err := time.Parse(time.RFC3339, c.IssuedLessThan)
	cmd.FailOnError(err, "failed to parse issuedLessThan")

	wkl, err := goodkey.LoadWeakRSASuffixes(c.WeakKeyFile)
	cmd.FailOnError(err, "failed to load weak key list")

	uri, err := c.DBConfig.URL()
	cmd.FailOnError(err, "Failed to load DB URI")
	db, err := sql.Open("mysql", uri)
	cmd.FailOnError(err, "failed to connect to DB")

	work := make(chan certInfo, 5000)

	go getCerts(work, moreThan, lessThan, db)
	doWork(work, c.Parallelism, wkl, log)
}
