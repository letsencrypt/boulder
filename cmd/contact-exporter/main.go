package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
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
	var contactsJSON [][]byte
	_, err := c.dbMap.Select(
		&contactsJSON,
		`SELECT contact AS active_contact
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

	contactMap := make(map[string]struct{}, len(contactsJSON))
	for _, contactRaw := range contactsJSON {
		var contactList []string
		err := json.Unmarshal(contactRaw, &contactList)
		if err != nil {
			c.log.AuditErr(
				fmt.Sprintf("couldn't unmarshal contact JSON %#v: %s\n",
					contactRaw, err))
			continue
		}
		for _, entry := range contactList {
			// Only include email addresses
			if strings.HasPrefix(entry, "mailto:") {
				address := strings.TrimPrefix(entry, "mailto:")
				// Using the contactMap to deduplicate addresses
				contactMap[address] = struct{}{}
			}
		}
	}

	// Convert the de-dupe'd map back to a slice, sort it
	var contacts []string
	for contact := range contactMap {
		contacts = append(contacts, contact)
	}
	sort.Strings(contacts)
	return contacts, nil
}

func writeContacts(contacts []string, outFile string) error {
	data := []byte(strings.Join(contacts, "\n") + "\n")

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
