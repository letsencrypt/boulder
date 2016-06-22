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
	"github.com/letsencrypt/boulder/mail"
	"github.com/letsencrypt/boulder/sa"
)

type contactExporter struct {
	log   blog.Logger
	dbMap *gorp.DbMap
	clk   clock.Clock
}

func (c contactExporter) findContacts() ([]*mail.MailerDestination, error) {
	var contactsList []*mail.MailerDestination
	_, err := c.dbMap.Select(
		&contactsList,
		`SELECT id, contact
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

	for _, contact := range contactsList {
		var contactFields []string
		err := json.Unmarshal(contact.Contact, &contactFields)
		if err != nil {
			c.log.AuditErr(
				fmt.Sprintf("couldn't unmarshal contact JSON %#v: %s\n",
					contact.Contact, err))
			continue
		}
		for _, entry := range contactFields {
			// Set the Email field if there is a `mailto:` address
			if strings.HasPrefix(entry, "mailto:") {
				address := strings.TrimPrefix(entry, "mailto:")
				contact.Email = address
			}
		}
	}

	return contactsList, nil
}

func contactsToEmails(contactList []*mail.MailerDestination) []string {
	contactMap := make(map[string]struct{}, len(contactList))
	for _, contact := range contactList {
		if strings.TrimSpace(contact.Email) == "" {
			continue
		}
		// Using the contactMap to deduplicate addresses
		contactMap[contact.Email] = struct{}{}
	}
	var contacts []string
	// Convert the de-dupe'd map back to a slice, sort it
	for contact := range contactMap {
		contacts = append(contacts, contact)
	}
	sort.Strings(contacts)
	return contacts
}

func writeContacts(contactsList []*mail.MailerDestination, outfile string) error {
	data, err := json.Marshal(contactsList)
	data = append(data, "\n"...)
	if err != nil {
		return err
	}

	if outfile != "" {
		return ioutil.WriteFile(outfile, data, 0644)
	} else {
		fmt.Printf("%s", data)
		return nil
	}
}

func writeEmails(contactList []*mail.MailerDestination, outFile string) error {
	contacts := contactsToEmails(contactList)

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
	emailOut := flag.Bool("emails", false, "Export contact email addresses (defaults to registration IDs).")
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

	if *emailOut {
		err = writeEmails(contacts, *outFile)
	} else {
		err = writeContacts(contacts, *outFile)
	}
	cmd.FailOnError(err, fmt.Sprintf("Could not write contacts to outfile '%s'", *outFile))
}
