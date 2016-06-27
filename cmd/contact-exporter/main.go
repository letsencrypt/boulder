package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/gorp.v1"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

type contactExporter struct {
	log   blog.Logger
	dbMap *gorp.DbMap
	clk   clock.Clock
}

type contactJSON struct {
	ID      int64  `json:"id"`
	Contact []byte `json:"-"`
}

// Find all registration contacts with unexpired certificates.
func (c contactExporter) findContacts() ([]contactJSON, error) {
	var contactsList []contactJSON
	_, err := c.dbMap.Select(
		&contactsList,
		`SELECT id
		FROM registrations
		WHERE contact != 'null' AND
			id IN (
				SELECT registrationID
				FROM certificates
				WHERE expires >= :expireCutoff
			);`,
		map[string]interface{}{
			"expireCutoff": c.clk.Now(),
		})
	if err != nil {
		c.log.AuditErr(fmt.Sprintf("Error finding contacts: %s", err))
		return nil, err
	}

	return contactsList, nil
}

// The `writeContacts` function produces a file containing JSON serialized
// contact objects
func writeContacts(contactsList []contactJSON, outfile string) error {
	data, err := json.Marshal(contactsList)
	if err != nil {
		return err
	}
	data = append(data, "\n"...)

	if outfile != "" {
		return ioutil.WriteFile(outfile, data, 0644)
	} else {
		fmt.Printf("%s", data)
		return nil
	}
}

func main() {
	outFile := flag.String("outfile", "", "File to write contacts to (defaults to stdout).")
	type config struct {
		ContactExporter struct {
			cmd.DBConfig
			cmd.PasswordConfig
		}
	}
	configFile := flag.String("config", "", "File containing a JSON config.")

	flag.Parse()
	if outFile == nil {
		flag.Usage()
		os.Exit(1)
	}

	_, log := cmd.StatsAndLogging(cmd.StatsdConfig{}, cmd.SyslogConfig{StdoutLevel: 7})

	configData, err := ioutil.ReadFile(*configFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %s", *configFile))
	var cfg config
	err = json.Unmarshal(configData, &cfg)
	cmd.FailOnError(err, "Unmarshaling config")

	dbURL, err := cfg.ContactExporter.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, 10)
	cmd.FailOnError(err, "Could not connect to database")

	exporter := contactExporter{
		log:   log,
		dbMap: dbMap,
		clk:   cmd.Clock(),
	}

	contacts, err := exporter.findContacts()
	cmd.FailOnError(err, "Could not find contacts")

	err = writeContacts(contacts, *outFile)
	cmd.FailOnError(err, fmt.Sprintf("Could not write contacts to outfile '%s'", *outFile))
}
