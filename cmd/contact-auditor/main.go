package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/sa"
)

type contactAuditor struct {
	dbMap  *db.WrappedMap
	logger blog.Logger
	clk    clock.Clock
	grace  time.Duration
}

// queryResult is receiver for gorp select queries.
type queryResult struct {
	// Receiver for the `id` column.
	ID int64

	// Receiver for the `contact` column.
	Contact []byte

	// Receiver for e-mail addresses unmarshalled from the `Contact`
	// field.
	addresses []string
}

// queryResults is a selectable 'holder' for gorp queries.
type queryResults []*queryResult

// collectContacts queries the database for all IDs and contacts with
// certificates whose expiration falls within the expiry cuttoff.
func (c contactAuditor) collectContacts() (queryResults, error) {
	var holder queryResults
	// Setting isolation level to `READ UNCOMMITTED` improves
	// performance at the cost of consistency. For our purposes this is
	// fine.
	_, err := c.dbMap.Exec("SET SESSION TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;")
	if err != nil {
		return nil, fmt.Errorf("error while setting transaction level: %s", err)
	}

	// Run query.
	_, err = c.dbMap.Select(
		&holder,
		`SELECT DISTINCT r.id, r.contact
	    FROM registrations AS r
		    INNER JOIN certificates AS c on c.registrationID = r.id
	    WHERE r.contact != '[]'
		    AND c.expires >= :expireCutoff`,
		map[string]interface{}{
			"expireCutoff": c.clk.Now().Add(-c.grace),
		})
	if err != nil {
		return nil, fmt.Errorf("error while querying database: %s", err)
	}
	return holder, nil
}

// unmarshalAddresses unmarshalls the `Contact` field of the inner
// `queryResult` and extracts the email addresses.
func (r *queryResult) unmarshalAddresses() error {
	var contactFields []string
	err := json.Unmarshal(r.Contact, &contactFields)
	if err != nil {
		return err
	}
	for _, entry := range contactFields {
		if strings.HasPrefix(entry, "mailto:") {
			r.addresses = append(r.addresses, strings.TrimPrefix(entry, "mailto:"))
		}
	}
	return nil
}

// run extracts email addresses from the database and attempts to
// validate each.
func (c contactAuditor) run() (queryResults, error) {
	results, err := c.collectContacts()
	if err != nil {
		return nil, err
	}
	for _, result := range results {
		err = result.unmarshalAddresses()
		if err != nil {
			return nil, err
		}
		for _, address := range result.addresses {
			err := policy.ValidEmail(address)
			if err != nil {
				c.logger.Errf(
					"validation failed for address: %q with ID: %d for reason: %q", address, result.ID, err)
				continue
			}
		}
	}
	return results, nil
}

func main() {
	configFile := flag.String("config", "", "File containing a JSON config.")
	grace := flag.Duration(
		"grace", 2*24*time.Hour, "Include contacts of subscribers with certificates that expired <grace>\n period from now")
	flag.Parse()

	logger := cmd.NewLogger(cmd.SyslogConfig{StdoutLevel: 7})

	configData, err := ioutil.ReadFile(*configFile)
	cmd.FailOnError(err, fmt.Sprintf("Error while reading file: %q", *configFile))

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

	// Parse database connect URL.
	dbURL, err := cfg.ContactAuditor.DB.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")

	// Setup database client.
	dbSettings := sa.DbSettings{
		MaxOpenConns:    cfg.ContactAuditor.DB.MaxOpenConns,
		MaxIdleConns:    cfg.ContactAuditor.DB.MaxIdleConns,
		ConnMaxLifetime: cfg.ContactAuditor.DB.ConnMaxLifetime.Duration,
		ConnMaxIdleTime: cfg.ContactAuditor.DB.ConnMaxIdleTime.Duration,
	}

	dbMap, err := sa.NewDbMap(dbURL, dbSettings)
	cmd.FailOnError(err, "Couldn't setup database client")

	// Setup and run contact-auditor.
	auditor := contactAuditor{
		dbMap:  dbMap,
		logger: logger,
		clk:    clock.New(),
		grace:  *grace,
	}
	logger.Infof("running contact-auditor with a grace period of >= %s", grace.String())
	_, err = auditor.run()
	if err != nil {
		logger.Errf("problem encountered while running audit: %s", err)
	}
}
