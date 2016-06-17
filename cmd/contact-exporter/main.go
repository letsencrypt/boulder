package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

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

func (c contactExporter) findContacts() ([]string, error) {
	var contactsJSON []string
	var contacts []string

	_, err := c.dbMap.Select(
		&contactsJSON,
		`
			SELECT DISTINCT (contact) AS active_contact
			FROM registrations
			WHERE contact != 'null' AND
				id IN (
					SELECT registrationID
					FROM certificates
					WHERE expires >= :expireCutoff
				)
			;
			`,
		map[string]interface{}{
			"expireCutoff": c.clk.Now(),
		})
	if err != nil {
		c.log.AuditErr(fmt.Sprintf("contact-exporter: Error finding contacts: %s", err))
		return nil, err
	}

	for _, contactRaw := range contactsJSON {
		var contactList []string
		err := json.Unmarshal([]byte(contactRaw), &contactList)
		if err != nil {
			c.log.AuditErr(
				fmt.Sprintf("contact-exporter: couldn't unmarshal contact JSON %#v: %s\n",
					contactRaw, err))
			continue
		}
		for _, entry := range contactList {
			// Only include email addresses
			if strings.HasPrefix(entry, "mailto:") {
				contacts = append(contacts, strings.TrimPrefix(entry, "mailto:"))
			}
		}
	}

	return contacts, nil
}

func writeContacts(contacts []string, outFile string) error {
	data := []byte(strings.Join(contacts, "\n"))

	if outFile != "" {
		return ioutil.WriteFile(outFile, data, 0644)
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

	seven := 7
	_, log := cmd.StatsAndLogging(cmd.StatsdConfig{}, cmd.SyslogConfig{StdoutLevel: &seven})

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
