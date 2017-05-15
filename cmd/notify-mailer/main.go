package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
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

type regID struct {
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

func (m *mailer) printStatus(to string, cur, total int, start time.Time) {
	// Should never happen
	if total <= 0 || cur < 0 || cur > total {
		m.log.AuditErr(fmt.Sprintf(
			"invalid cur (%d) or total (%d)\n", cur, total))
	}
	completion := (float32(cur) / float32(total)) * 100
	now := m.clk.Now()
	elapsed := now.Sub(start)
	m.log.Info(fmt.Sprintf("Sending to %q. Message %d of %d [%.2f%%]. Elapsed: %s\n",
		to, cur, total, completion, elapsed.String()))
}

func (m *mailer) run() error {
	if err := m.ok(); err != nil {
		return err
	}

	destinations, err := m.resolveDestinations()
	if err != nil {
		return err
	}

	err = m.mailer.Connect()
	if err != nil {
		return err
	}
	defer func() {
		_ = m.mailer.Close()
	}()

	startTime := m.clk.Now()

	for i, dest := range destinations {
		m.printStatus(dest, i, len(destinations), startTime)
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
func (m *mailer) resolveDestinations() ([]string, error) {
	var regs []regID
	err := json.Unmarshal(m.destinations, &regs)
	if err != nil {
		return nil, err
	}

	// If there is no endpoint specified, use the total # of destinations
	if m.checkpoint.end == 0 || m.checkpoint.end > len(regs) {
		m.checkpoint.end = len(regs)
	}

	// Do not allow a start larger than the # of destinations
	if m.checkpoint.start > len(regs) {
		return nil, fmt.Errorf(
			"interval start value (%d) is greater than number of destinations (%d)",
			m.checkpoint.start,
			len(regs))
	}

	var contactsList []string
	for _, c := range regs[m.checkpoint.start:m.checkpoint.end] {
		// Get the email address for the reg ID
		emails, err := emailsForReg(c.ID, m.dbMap)
		if err != nil {
			return nil, err
		}

		for _, email := range emails {
			if strings.TrimSpace(email) == "" {
				continue
			}
			contactsList = append(contactsList, email)
		}
	}
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
	if err == sql.ErrNoRows {
		return []string{}, nil
	}
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

const usageIntro = `
Introduction:

The notification mailer exists to send a fixed message to the contact associated
with a list of registration IDs. The attributes of the message (from address,
subject, and message content) are provided by the command line arguments. The
message content is used verbatim and must be provided as a path to a plaintext
file via the -body argument. A list of registration IDs should be provided via
the -toFile argument as a path to a plaintext file containing JSON of the form:

  [
   { "id": 1 },
   ...
   { "id": n }
  ]

To help the operator gain confidence in the mailing run before committing fully
three safety features are supported: dry runs, checkpointing and a sleep
interval.

The -dryRun=true flag will use a mock mailer that prints message content to
stdout instead of performing an SMTP transaction with a real mailserver. This
can be used when the initial parameters are being tweaked to ensure no real
emails are sent. Using -dryRun=false will send real email.

Checkpointing is supported via the -start and -end arguments. The -start flag
specifies which registration ID of the -toFile to start processing at.
Similarly, the -end flag specifies which registration ID of the -toFile to end
processing at. In combination these can be used to process only a fixed number
of recipients at a time, and to resume mailing after early termination.

During mailing the -sleep argument is used to space out individual messages.
This can be used to ensure that the mailing happens at a steady pace with ample
opportunity for the operator to terminate early in the event of error. The
-sleep flag honours durations with a unit suffix (e.g. 1m for 1 minute, 10s for
10 seconds, etc). Using -sleep=0 will disable the sleep and send at full speed.

Examples:
  Send an email with subject "Hello!" from the email "hello@goodbye.com" with
  the contents read from "test_msg_body.txt" to every email associated with the
  registration IDs listed in "test_reg_recipients.json", sleeping 10 seconds
  between each message:

  notify-mailer -config test/config/notify-mailer.json -body
    cmd/notify-mailer/testdata/test_msg_body.txt -from hello@goodbye.com
    -toFile cmd/notify-mailer/testdata/test_msg_recipients.json -subject "Hello!"
    -sleep 10s -dryRun=false

  Do the same, but only to the first 100 recipient IDs:

  notify-mailer -config test/config/notify-mailer.json
    -body cmd/notify-mailer/testdata/test_msg_body.txt -from hello@goodbye.com
    -toFile cmd/notify-mailer/testdata/test_msg_recipients.json -subject "Hello!"
    -sleep 10s -end 100 -dryRun=false

  Send the message, but start at the 200th ID of the recipients file, ending after
  100 registration IDs, and as a dry-run:

  notify-mailer -config test/config/notify-mailer.json 
    -body cmd/notify-mailer/testdata/test_msg_body.txt -from hello@goodbye.com 
    -toFile cmd/notify-mailer/testdata/test_msg_recipients.json -subject "Hello!"
    -sleep 10s -start 200 -end 300 -dryRun=true

Required arguments:
- body
- config
- from
- subject
- toFile`

func main() {
	from := flag.String("from", "", "From header for emails. Must be a bare email address.")
	subject := flag.String("subject", "", "Subject of emails")
	toFile := flag.String("toFile", "", "File containing a JSON array of registration IDs to send to.")
	bodyFile := flag.String("body", "", "File containing the email body in plain text format.")
	dryRun := flag.Bool("dryRun", true, "Whether to do a dry run.")
	sleep := flag.Duration("sleep", 60*time.Second, "How long to sleep between emails.")
	start := flag.Int("start", 0, "Line of input file to start from.")
	end := flag.Int("end", 99999999, "Line of input file to end before.")
	reconnBase := flag.Duration("reconnectBase", 1*time.Second, "Base sleep duration between reconnect attempts")
	reconnMax := flag.Duration("reconnectMax", 5*60*time.Second, "Max sleep duration between reconnect attempts after exponential backoff")
	type config struct {
		NotifyMailer struct {
			cmd.DBConfig
			cmd.PasswordConfig
			cmd.SMTPConfig
			Features map[string]bool
		}
		Syslog cmd.SyslogConfig
	}
	configFile := flag.String("config", "", "File containing a JSON config.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n\n", usageIntro)
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if *from == "" || *subject == "" || *bodyFile == "" || *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	configData, err := ioutil.ReadFile(*configFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %q", *configFile))
	var cfg config
	err = json.Unmarshal(configData, &cfg)
	cmd.FailOnError(err, "Unmarshaling config")
	err = features.Set(cfg.NotifyMailer.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	scope, log := cmd.StatsAndLogging(cfg.Syslog)
	defer log.AuditPanic()

	dbURL, err := cfg.NotifyMailer.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, 10)
	cmd.FailOnError(err, "Could not connect to database")
	go sa.ReportDbConnCount(dbMap, scope)

	// Load email body
	body, err := ioutil.ReadFile(*bodyFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %q", *bodyFile))

	address, err := mail.ParseAddress(*from)
	cmd.FailOnError(err, fmt.Sprintf("Parsing %q", *from))

	toBody, err := ioutil.ReadFile(*toFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %q", *toFile))

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
			*address,
			log,
			scope,
			*reconnBase,
			*reconnMax)
	}

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
