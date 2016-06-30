package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/mail"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	bmail "github.com/letsencrypt/boulder/mail"
	"github.com/letsencrypt/boulder/sa"
)

type mailer struct {
	clk           clock.Clock
	log           blog.Logger
	dbMap         dbSelector
	mailer        bmail.Mailer
	subject       string
	emailTemplate string
	destinations  []byte
	checkpoint    interval
	sleepInterval time.Duration
}

type interval struct {
	start int
	end   int
}

type contact struct {
	ID int
}

type contactJSON struct {
	ID      int
	Contact []byte
}

func (i *interval) ok() error {
	if i.start < 0 || i.end < 0 {
		return fmt.Errorf(
			"interval start (%d) and end (%d) must both be positive integers",
			i.start, i.end)
	}

	if i.start > i.end && i.end != 0 {
		return fmt.Errorf(
			"interval start value (%d) is greater than end value (%d)",
			i.start, i.end)
	}

	return nil
}

func (m *mailer) ok() error {
	// Make sure the checkpoint range is OK
	if checkpointErr := m.checkpoint.ok(); checkpointErr != nil {
		return checkpointErr
	}

	// Do not allow a negative sleep interval
	if m.sleepInterval < 0 {
		return fmt.Errorf(
			"sleep interval (%d) is < 0", m.sleepInterval)
	}

	return nil
}

func (m *mailer) run() error {
	if err := m.ok(); err != nil {
		return err
	}

	destinations, err := m.resolveDestinations()
	if err != nil {
		return err
	}

	for _, dest := range destinations {
		if strings.TrimSpace(dest) == "" {
			continue
		}
		err := m.mailer.SendMail([]string{dest}, m.subject, m.emailTemplate)
		if err != nil {
			return err
		}
		m.clk.Sleep(m.sleepInterval)
	}
	return nil
}

// Resolves each reg ID to the most up-to-date contact email.
// The email addresses are returned deduplicated and sorted.
func (m *mailer) resolveDestinations() ([]string, error) {
	var contacts []contact
	err := json.Unmarshal(m.destinations, &contacts)
	if err != nil {
		return nil, err
	}

	// If there is no endpoint specified, use the total # of destinations
	if m.checkpoint.end == 0 {
		m.checkpoint.end = len(contacts)
	}

	// Do not allow a start larger than the # of destinations
	if m.checkpoint.start > len(contacts) {
		return nil, fmt.Errorf(
			"interval start value (%d) is greater than number of destinations (%d)",
			m.checkpoint.start,
			len(contacts))
	}

	contactMap := make(map[string]struct{}, len(contacts))
	for _, c := range contacts[m.checkpoint.start:m.checkpoint.end] {
		// Get the email address for the reg ID
		emails, err := emailsForReg(c.ID, m.dbMap)
		if err != nil {
			return nil, err
		}

		for _, email := range emails {
			if strings.TrimSpace(email) == "" {
				continue
			}
			// Using the contactMap to deduplicate addresses
			contactMap[email] = struct{}{}
		}
	}

	var contactsList []string
	// Convert the de-dupe'd map back to a slice, sort it
	for contact := range contactMap {
		contactsList = append(contactsList, contact)
	}
	sort.Strings(contactsList)
	return contactsList, nil
}

// Since the only thing we use from gorp is the SelectOne method on the
// gorp.DbMap object, we just define an interface with that method
// instead of importing all of gorp. This facilitates mock implementations for
// unit tests
type dbSelector interface {
	SelectOne(holder interface{}, query string, args ...interface{}) error
}

// Finds the email addresses associated with a reg ID
func emailsForReg(id int, dbMap dbSelector) ([]string, error) {
	var contact contactJSON
	err := dbMap.SelectOne(&contact,
		`SELECT id, contact
		FROM registrations
		WHERE contact != 'null' AND id = :id;`,
		map[string]interface{}{
			"id": id,
		})
	if err != nil {
		return nil, err
	}

	var contactFields []string
	var addresses []string
	err = json.Unmarshal(contact.Contact, &contactFields)
	if err != nil {
		return nil, err
	}
	for _, entry := range contactFields {
		if strings.HasPrefix(entry, "mailto:") {
			addresses = append(addresses, strings.TrimPrefix(entry, "mailto:"))
		}
	}
	return addresses, nil
}

func main() {
	from := flag.String("from", "", "From header for emails. Must be a bare email address.")
	subject := flag.String("subject", "", "Subject of emails")
	toFile := flag.String("toFile", "", "File containing a list of email addresses to send to, one per file.")
	bodyFile := flag.String("body", "", "File containing the email body in plain text format.")
	dryRun := flag.Bool("dryRun", true, "Whether to do a dry run.")
	sleep := flag.Duration("sleep", 60*time.Second, "How long to sleep between emails.")
	start := flag.Int("start", 0, "Line of input file to start from.")
	end := flag.Int("end", 99999999, "Line of input file to end before.")
	type config struct {
		NotifyMailer struct {
			cmd.DBConfig
			cmd.PasswordConfig
			cmd.SMTPConfig
		}
	}
	configFile := flag.String("config", "", "File containing a JSON config.")

	flag.Parse()
	if from == nil || subject == nil || bodyFile == nil || configFile == nil {
		flag.Usage()
		os.Exit(1)
	}

	_, log := cmd.StatsAndLogging(cmd.StatsdConfig{}, cmd.SyslogConfig{StdoutLevel: 7})

	configData, err := ioutil.ReadFile(*configFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %s", *configFile))
	var cfg config
	err = json.Unmarshal(configData, &cfg)
	cmd.FailOnError(err, "Unmarshaling config")

	dbURL, err := cfg.NotifyMailer.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, 10)
	cmd.FailOnError(err, "Could not connect to database")

	// Load email body
	body, err := ioutil.ReadFile(*bodyFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %s", *bodyFile))

	address, err := mail.ParseAddress(*from)
	cmd.FailOnError(err, fmt.Sprintf("Parsing %s", *from))

	toBody, err := ioutil.ReadFile(*toFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %s", *toFile))

	checkpointRange := interval{
		start: *start,
		end:   *end,
	}

	var mailClient bmail.Mailer
	if *dryRun {
		mailClient = bmail.NewDryRun(*address, log)
	} else {
		smtpPassword, err := cfg.NotifyMailer.PasswordConfig.Pass()
		cmd.FailOnError(err, "Failed to load SMTP password")
		mailClient = bmail.New(
			cfg.NotifyMailer.Server,
			cfg.NotifyMailer.Port,
			cfg.NotifyMailer.Username,
			smtpPassword,
			*address)
	}
	err = mailClient.Connect()
	cmd.FailOnError(err, fmt.Sprintf("Connecting to %s:%s",
		cfg.NotifyMailer.Server, cfg.NotifyMailer.Port))
	defer func() {
		err = mailClient.Close()
		cmd.FailOnError(err, "Closing mail client")
	}()

	m := mailer{
		clk:           cmd.Clock(),
		log:           log,
		dbMap:         dbMap,
		mailer:        mailClient,
		subject:       *subject,
		destinations:  toBody,
		emailTemplate: string(body),
		checkpoint:    checkpointRange,
		sleepInterval: *sleep,
	}

	err = m.run()
	cmd.FailOnError(err, "mailer.send returned error")
}
