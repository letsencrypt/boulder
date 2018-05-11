package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"gopkg.in/go-gorp/gorp.v2"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

type idExporter struct {
	log   blog.Logger
	dbMap *gorp.DbMap
	clk   clock.Clock
	grace time.Duration
}

type id struct {
	ID int64 `json:"id"`
}

// Find all registration IDs with unexpired certificates.
func (c idExporter) findIDs() ([]id, error) {
	var idsList []id
	_, err := c.dbMap.Select(
		&idsList,
		`SELECT id
		FROM registrations
		WHERE contact != 'null' AND
			id IN (
				SELECT registrationID
				FROM certificates
				WHERE expires >= :expireCutoff
			);`,
		map[string]interface{}{
			"expireCutoff": c.clk.Now().Add(-c.grace),
		})
	if err != nil {
		c.log.AuditErrf("Error finding IDs: %s", err)
		return nil, err
	}

	return idsList, nil
}

func (c idExporter) findIDsForDomains(domains []string) ([]id, error) {
	var idsList []id
	for _, domain := range domains {
		// Pass the same list in each time, gorp will happily just append to the slice
		// instead of overwriting it each time
		// https://github.com/go-gorp/gorp/blob/2ae7d174a4cf270240c4561092402affba25da5e/select.go#L348-L355
		_, err := c.dbMap.Select(
			&idsList,
			`SELECT registrationID AS id FROM certificates
                         WHERE expires >= :expireCutoff AND
                         serial IN (
                           SELECT serial FROM issuedNames
                            WHERE reversedName = :reversedName
                         )`,
			map[string]interface{}{
				"expireCutoff": c.clk.Now().Add(-c.grace),
				"reversedName": sa.ReverseName(domain),
			},
		)
		if err != nil {
			if err == sql.ErrNoRows {
				continue
			}
			return nil, err
		}
	}

	return idsList, nil
}

// The `writeIDs` function produces a file containing JSON serialized
// contact objects
func writeIDs(idsList []id, outfile string) error {
	data, err := json.Marshal(idsList)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if outfile != "" {
		return ioutil.WriteFile(outfile, data, 0644)
	}

	fmt.Printf("%s", data)
	return nil
}

const usageIntro = `
Introduction:

The ID exporter exists to retrieve the IDs of all registered
users with currently unexpired certificates. This list of registration IDs can
then be given as input to the notification mailer to send bulk notifications.

The -grace parameter can be used to allow registrations with certificates that
have already expired to be included in the export. The argument is a Go duration
obeying the usual suffix rules (e.g. 24h).

Registration IDs are favoured over email addresses as the intermediate format in
order to ensure the most up to date contact information is used at the time of
notification. The notification mailer will resolve the ID to email(s) when the
mailing is underway, ensuring we use the correct address if a user has updated
their contact information between the time of export and the time of
notification.

The ID exporter's output will be JSON of the form:
  [
   { "id": 1 },
   ...
   { "id": n }
  ]

Examples:
  Export all registration IDs with unexpired certificates to "regs.json":

  id-exporter -config test/config/id-exporter.json -outfile regs.json

  Export all registration IDs with certificates that are unexpired or expired
  within the last two days to "regs.json":

  id-exporter -config test/config/id-exporter.json -grace 48h -outfile
    "regs.json"

Required arguments:
- config
- outfile`

func main() {
	outFile := flag.String("outfile", "", "File to write contacts to (defaults to stdout).")
	grace := flag.Duration("grace", 2*24*time.Hour, "Include contacts with certificates that expired in < grace ago")
	domainsFile := flag.String("domains", "", "If provided only output contacts for certificates that contain at least one of the domains in the provided file. Provided file should contain one domain per line")
	type config struct {
		ContactExporter struct {
			cmd.DBConfig
			cmd.PasswordConfig
			Features map[string]bool
		}
	}
	configFile := flag.String("config", "", "File containing a JSON config.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n\n", usageIntro)
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	if *outFile == "" || *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	log := cmd.NewLogger(cmd.SyslogConfig{StdoutLevel: 7})

	configData, err := ioutil.ReadFile(*configFile)
	cmd.FailOnError(err, fmt.Sprintf("Reading %q", *configFile))
	var cfg config
	err = json.Unmarshal(configData, &cfg)
	cmd.FailOnError(err, "Unmarshaling config")
	err = features.Set(cfg.ContactExporter.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	dbURL, err := cfg.ContactExporter.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, 10)
	cmd.FailOnError(err, "Could not connect to database")

	exporter := idExporter{
		log:   log,
		dbMap: dbMap,
		clk:   cmd.Clock(),
		grace: *grace,
	}

	var ids []id
	if *domainsFile != "" {
		df, err := ioutil.ReadFile(*domainsFile)
		cmd.FailOnError(err, fmt.Sprintf("Could not read domains file %q", *domainsFile))
		ids, err = exporter.findIDsForDomains(strings.Split(string(df), "\n"))
		cmd.FailOnError(err, "Could not find IDs")
	} else {
		ids, err = exporter.findIDs()
		cmd.FailOnError(err, "Could not find IDs")
	}

	err = writeIDs(ids, *outFile)
	cmd.FailOnError(err, fmt.Sprintf("Could not write IDs to outfile %q", *outFile))
}
