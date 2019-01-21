package main

import (
	"bytes"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	bmail "github.com/letsencrypt/boulder/mail"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
)

type mailer struct {
	clk           clock.Clock
	log           blog.Logger
	dbMap         dbSelector
	mailer        bmail.Mailer
	subject       string
	emailTemplate *template.Template
	destinations  []recipient
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
	if total <= 0 || cur < 1 || cur > total {
		m.log.AuditErrf("invalid cur (%d) or total (%d)", cur, total)
	}
	completion := (float32(cur) / float32(total)) * 100
	now := m.clk.Now()
	elapsed := now.Sub(start)
	m.log.Infof("Sending to %q. Message %d of %d [%.2f%%]. Elapsed: %s",
		to, cur, total, completion, elapsed)
}

func (m *mailer) run() error {
	if err := m.ok(); err != nil {
		return err
	}

	err := m.resolveDestinations()
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

	for i, dest := range m.destinations {
		if dest.address == "" {
			m.log.Infof("Skipping %d; no address", dest.id)
			continue
		}
		m.printStatus(dest.address, i+1, len(m.destinations), startTime)
		if strings.TrimSpace(dest.address) == "" {
			continue
		}
		var mailBody bytes.Buffer
		err = m.emailTemplate.Execute(&mailBody, dest.extra)
		if err != nil {
			return err
		}
		if mailBody.Len() == 0 {
			return fmt.Errorf("email body was empty after interpolation.")
		}
		err := m.mailer.SendMail([]string{dest.address}, m.subject, mailBody.String())
		if err != nil {
			return err
		}
		m.clk.Sleep(m.sleepInterval)
	}
	return nil
}

// Resolves each reg ID to its contact emails, picks one of them, and adds that
// to the recipient data structure. Note that ACME and Boulder support multiple
// contact emails, but for the purpose of this mailing tool we only send to one
// email per account.
func (m *mailer) resolveDestinations() error {
	// If there is no endpoint specified, use the total # of destinations
	if m.checkpoint.end == 0 || m.checkpoint.end > len(m.destinations) {
		m.checkpoint.end = len(m.destinations)
	}

	// Do not allow a start larger than the # of destinations
	if m.checkpoint.start > len(m.destinations) {
		return fmt.Errorf(
			"interval start value (%d) is greater than number of destinations (%d)",
			m.checkpoint.start,
			len(m.destinations))
	}

	for i, r := range m.destinations[m.checkpoint.start:m.checkpoint.end] {
		// Get the email address for the reg ID
		emails, err := emailsForReg(r.id, m.dbMap)
		if err != nil {
			return err
		}

		for _, email := range emails {
			parsedEmail, err := mail.ParseAddress(email)
			if err != nil {
				m.log.Errf("unparseable email for reg ID %d : %q", r.id, email)
				continue
			}
			m.destinations[i].address = parsedEmail.Address
		}
	}
	return nil
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

type recipient struct {
	id      int
	address string
	extra   map[string]string
}

// readRecipientsList reads a CSV filename and parses that file into a list of
// recipient structs. Columns after the first are parsed into a per-recipient
// map from column name -> value.
func readRecipientsList(filename string) ([]recipient, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	reader := csv.NewReader(f)
	record, err := reader.Read()
	if err != nil {
		return nil, err
	}
	if record[0] != "id" {
		return nil, fmt.Errorf("First field of CSV input must be an ID.")
	}
	var columnNames []string
	for _, v := range record[1:] {
		columnNames = append(columnNames, strings.TrimSpace(v))
	}

	results := []recipient{}
	for {
		record, err := reader.Read()
		if err == io.EOF {
			return results, nil
		}
		if err != nil {
			return nil, err
		}
		id, err := strconv.Atoi(record[0])
		if err != nil {
			return nil, err
		}
		recip := recipient{
			id:    id,
			extra: make(map[string]string),
		}
		for i, v := range record[1:] {
			recip.extra[columnNames[i]] = v
		}
		results = append(results, recip)
	}
}

const usageIntro = `
Introduction:

The notification mailer exists to send a message to the contact associated
with a list of registration IDs. The attributes of the message (from address,
subject, and message content) are provided by the command line arguments. The
message content is provided as a path to a template file via the -body argument.

Provide a list of recipient user ids in a CSV file passed with the -recipientList
flag. The CSV file must have "id" as the first column and may have additional
fields to be interpolated into the email template:

	id, lastIssuance
	1234, "from example.com 2018-12-01"
	5678, "from example.net 2018-12-13"

The additional fields will be interpolated with Golang templating, e.g.:

  Your last issuance was {{ .lastIssuance }}

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

Notify-mailer will de-duplicate email addresses, but only within the range given
by the -start and -end arguments. For instance, if you split up an email job into
five batches using -start and -end, there's a possibility that a given email address
may receive up to five emails, if that email address is registered across multiple
accounts.

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
    -recipientList cmd/notify-mailer/testdata/test_msg_recipients.csv -subject "Hello!"
    -sleep 10s -dryRun=false

  Do the same, but only to the first 100 recipient IDs:

  notify-mailer -config test/config/notify-mailer.json
    -body cmd/notify-mailer/testdata/test_msg_body.txt -from hello@goodbye.com
    -recipientList cmd/notify-mailer/testdata/test_msg_recipients.csv -subject "Hello!"
    -sleep 10s -end 100 -dryRun=false

  Send the message, but start at the 200th ID of the recipients file, ending after
  100 registration IDs, and as a dry-run:

  notify-mailer -config test/config/notify-mailer.json 
    -body cmd/notify-mailer/testdata/test_msg_body.txt -from hello@goodbye.com 
    -recipientList cmd/notify-mailer/testdata/test_msg_recipients.csv -subject "Hello!"
    -sleep 10s -start 200 -end 300 -dryRun=true

Required arguments:
- body
- config
- from
- subject
- recipientList`

func main() {
	from := flag.String("from", "", "From header for emails. Must be a bare email address.")
	subject := flag.String("subject", "", "Subject of emails")
	recipientListFile := flag.String("recipientList", "", "File containing a CSV list of registration IDs and extra info.")
	bodyFile := flag.String("body", "", "File containing the email body in Golang template format.")
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
	if *from == "" || *subject == "" || *bodyFile == "" || *configFile == "" ||
		*recipientListFile == "" {
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

	log := cmd.NewLogger(cfg.Syslog)
	defer log.AuditPanic()

	dbURL, err := cfg.NotifyMailer.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, 10)
	cmd.FailOnError(err, "Could not connect to database")

	// Load email body
	body, err := ioutil.ReadFile(*bodyFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %q", *bodyFile))
	template, err := template.New("email").Parse(string(body))
	cmd.FailOnError(err, "Parsing template")

	address, err := mail.ParseAddress(*from)
	cmd.FailOnError(err, fmt.Sprintf("Parsing %q", *from))

	recipients, err := readRecipientsList(*recipientListFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %q", *recipientListFile))

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
			nil,
			*address,
			log,
			metrics.NewNoopScope(),
			*reconnBase,
			*reconnMax)
	}

	m := mailer{
		clk:           cmd.Clock(),
		log:           log,
		dbMap:         dbMap,
		mailer:        mailClient,
		subject:       *subject,
		destinations:  recipients,
		emailTemplate: template,
		checkpoint:    checkpointRange,
		sleepInterval: *sleep,
	}

	err = m.run()
	cmd.FailOnError(err, "mailer.send returned error")
}
