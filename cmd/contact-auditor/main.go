package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/policy"
)

var queryInterrupted bool

type contactAuditor struct {
	db     *sql.DB
	logger blog.Logger
	clk    clock.Clock
	grace  time.Duration
}

type result struct {
	// Receiver for the `id` column.
	ID int64

	// Receiver for the `contact` column.
	Contact  []byte
	contacts []string
}

func (r *result) unmarshalContact() error {
	var contact []string
	err := json.Unmarshal(r.Contact, &contact)
	if err != nil {
		return err
	}
	r.contacts = append(r.contacts, contact...)
	return nil
}

func (r *result) validateContact() error {
	// Setup a buffer to store any validation problems we encounter.
	var probsBuff strings.Builder

	// Helper to write validation problems to our buffer.
	writeProb := func(contact string, prob string) {
		// Add validation problem to buffer.
		probsBuff.WriteString(fmt.Sprintf("[ %q: %q ] ", contact, prob))
	}

	for _, contact := range r.contacts {
		if strings.HasPrefix(contact, "mailto:") {
			err := policy.ValidEmail(strings.TrimPrefix(contact, "mailto:"))
			if err != nil {
				writeProb(contact, err.Error())
			}
		} else {
			writeProb(contact, "missing 'mailto:' prefix")
		}
	}

	if probsBuff.String() != "" {
		return errors.New(probsBuff.String())
	}
	return nil
}

type results struct {
	entries []*result
	logger  blog.Logger
}

func (r *results) unmarshalContacts() {
	for _, result := range r.entries {
		err := result.unmarshalContact()
		if err != nil {
			r.logger.Errf("Unmarshal failed for ID: %d due to: %s", result.ID, err)
			continue
		}
	}
}

func (r results) validateContacts() {
	for _, result := range r.entries {
		err := result.validateContact()
		if err != nil {
			r.logger.Errf("Validation failed for ID: %s due to: %s", result.ID, err)
			continue
		}
	}
}

// collectContacts queries the database for all IDs and contacts with
// unexpired certificates.
func (c contactAuditor) collectContacts() (*results, error) {
	// Setting isolation level to `READ UNCOMMITTED` improves
	// performance at the cost of consistency.
	_, err := c.db.Exec("SET SESSION TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;")
	if err != nil {
		return nil, fmt.Errorf("error setting db trancaction isolation level: %s", err)
	}

	rows, err := c.db.Query(
		fmt.Sprintf(
			"%s '%s';",
			`SELECT DISTINCT r.id, r.contact
			FROM registrations AS r
				INNER JOIN certificates AS c on c.registrationID = r.id
			WHERE r.contact NOT IN ('[]', 'null')
				AND c.expires >=`,
			c.clk.Now().Add(-c.grace).Format("2006-01-02T15:04:05Z")),
	)
	if err != nil {
		return nil, fmt.Errorf("error performing db query: %s", err)
	}

	c.logger.Infof("Gathering query results")
	results := results{logger: c.logger}
	for rows.Next() {
		var result result
		err := rows.Scan(&result.ID, &result.Contact)
		if err != nil {
			return nil, err
		}
		results.entries = append(results.entries, &result)
	}

	// Ensure the query wasn't interrupted before it could complete.
	err = rows.Close()
	if err != nil {
		// Log an error but continue processing results.
		c.logger.Errf("Query interrupted due to: %s", err)
		queryInterrupted = true
	} else {
		c.logger.Info("Query completed successfully")
	}
	return &results, nil
}

func (c contactAuditor) run() (*results, error) {
	c.logger.Infof("Beginning database query")
	results, err := c.collectContacts()
	if err != nil {
		return nil, err
	}

	c.logger.Infof("Processing %d results", len(results.entries))
	results.unmarshalContacts()
	results.validateContacts()
	return results, nil
}

func main() {
	configFile := flag.String("config", "", "File containing a JSON config.")
	grace := flag.Duration(
		"grace", 2*24*time.Hour, "Include contacts of subscribers with certificates that expired <grace>\n period from now")
	flag.Parse()

	logger := cmd.NewLogger(cmd.SyslogConfig{StdoutLevel: 7})

	configData, err := ioutil.ReadFile(*configFile)
	cmd.FailOnError(err, fmt.Sprintf("Error reading file: %q", *configFile))

	// Load JSON configuration.
	type config struct {
		ContactAuditor struct {
			DB cmd.DBConfig
			cmd.PasswordConfig
		}
	}

	var cfg config
	err = json.Unmarshal(configData, &cfg)
	cmd.FailOnError(err, "Couldn't unmarshal config")

	// Setup database client.
	dbURL, err := cfg.ContactAuditor.DB.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")

	db, err := sql.Open("mysql", fmt.Sprintf("%s?readTimeout=14s&writeTimeout=14s&timeout=1s", dbURL))
	cmd.FailOnError(err, "Couldn't setup database client")

	// Apply database settings.
	db.SetMaxOpenConns(cfg.ContactAuditor.DB.MaxOpenConns)
	db.SetMaxIdleConns(cfg.ContactAuditor.DB.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ContactAuditor.DB.ConnMaxLifetime.Duration)
	db.SetConnMaxIdleTime(cfg.ContactAuditor.DB.ConnMaxIdleTime.Duration)

	// Setup and run contact-auditor.
	auditor := contactAuditor{
		db:     db,
		logger: logger,
		clk:    clock.New(),
		grace:  *grace,
	}

	logger.Infof("Running contact-auditor with a grace period of >= %s", grace.String())

	_, err = auditor.run()
	cmd.FailOnError(err, "Audit was interrupted")

	if queryInterrupted {
		cmd.Fail("Audit was interrupted, results may be incomplete, see log for details")
	} else {
		logger.Info("Audit finished successfully")
	}
}
