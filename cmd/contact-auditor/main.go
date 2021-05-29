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

// beginAuditQuery executes the audit query and returns a cursor used to
// stream the results.
func (c contactAuditor) beginAuditQuery() (*sql.Rows, error) {
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
	return rows, nil
}

// run retrieves a cursor from `beginAuditQuery` and then audits the
// `contact` column of all returned rows for abnormalities or policy
// violations.
func (c contactAuditor) run(resChan chan *result) error {
	c.logger.Infof("Beginning database query")
	rows, err := c.beginAuditQuery()
	if err != nil {
		return err
	}

	for rows.Next() {
		var res result
		err := rows.Scan(&res.ID, &res.Contact)
		if err != nil {
			return err
		}

		err = res.unmarshalContact()
		if err != nil {
			c.logger.Errf("Unmarshal failed for ID: %d due to: %s", res.ID, err)
		}

		err = res.validateContact()
		if err != nil {
			c.logger.Errf("Validation failed for ID: %s due to: %s", res.ID, err)
		}

		// Only used for testing.
		if resChan != nil {
			resChan <- &res
		}
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

	// Only used for testing.
	if resChan != nil {
		close(resChan)
	}

	return nil
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

	// Setting isolation level to `READ UNCOMMITTED` improves
	// performance at the cost of consistency.
	_, err = db.Exec("SET SESSION TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;")
	cmd.FailOnError(err, "error setting db trancaction isolation level")

	// Setup and run contact-auditor.
	auditor := contactAuditor{
		db:     db,
		logger: logger,
		clk:    clock.New(),
		grace:  *grace,
	}

	logger.Infof("Running contact-auditor with a grace period of >= %s", grace.String())

	err = auditor.run(nil)
	cmd.FailOnError(err, "Audit was interrupted")

	if queryInterrupted {
		cmd.Fail("Audit was interrupted, results may be incomplete, see log for details")
	} else {
		logger.Info("Audit finished successfully")
	}

}
