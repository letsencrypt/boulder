package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
)

type idExporter struct {
	log   blog.Logger
	dbMap *db.WrappedMap
	clk   clock.Clock
	grace time.Duration
}

// resultEntry is a JSON marshalable exporter result entry.
type resultEntry struct {
	// ID is exported to support marshaling to JSON.
	ID int64 `json:"id"`

	// Hostname is exported to support marshaling to JSON. Not all queries
	// will fill this field, so it's JSON field tag marks at as
	// omittable.
	Hostname string `json:"hostname,omitempty"`
}

// reverseHostname converts (reversed) names sourced from the
// registrations table to standard hostnames.
func (r *resultEntry) reverseHostname() {
	r.Hostname = sa.ReverseName(r.Hostname)
}

// idExporterResults is passed as a selectable 'holder' for the results
// of id-exporter database queries
type idExporterResults []*resultEntry

// marshalToJSON returns JSON as bytes for all elements of the inner `id`
// slice.
func (i *idExporterResults) marshalToJSON() ([]byte, error) {
	data, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	return data, nil
}

// writeToFile writes the contents of the inner `ids` slice, as JSON, to
// a file
func (i *idExporterResults) writeToFile(outfile string) error {
	data, err := i.marshalToJSON()
	if err != nil {
		return err
	}
	return ioutil.WriteFile(outfile, data, 0644)
}

// Find all registration IDs with unexpired certificates.
func (c idExporter) findIDs() (idExporterResults, error) {
	var holder idExporterResults
	_, err := c.dbMap.Select(
		&holder,
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
	return holder, nil
}

// Find all registration IDs with unexpired certificates and gather an
// example hostname.
func (c idExporter) findIDsWithExampleHostnames() (idExporterResults, error) {
	var holder idExporterResults
	_, err := c.dbMap.Select(
		&holder,
		`SELECT SQL_BIG_RESULT
			cert.registrationID AS id,
			name.reversedName AS hostname
		FROM certificates AS cert
			INNER JOIN issuedNames AS name ON name.serial = cert.serial
		WHERE cert.expires >= :expireCutoff
		GROUP BY cert.registrationID;`,
		map[string]interface{}{
			"expireCutoff": c.clk.Now().Add(-c.grace),
		})
	if err != nil {
		c.log.AuditErrf("Error finding IDs and example hostnames: %s", err)
		return nil, err
	}

	for _, result := range holder {
		result.reverseHostname()
	}
	return holder, nil
}

func (c idExporter) findIDsForDomains(domains []string) (idExporterResults, error) {
	var holder idExporterResults
	for _, domain := range domains {
		// Pass the same list in each time, gorp will happily just append to the slice
		// instead of overwriting it each time
		// https://github.com/go-gorp/gorp/blob/2ae7d174a4cf270240c4561092402affba25da5e/select.go#L348-L355
		_, err := c.dbMap.Select(
			&holder,
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
			if db.IsNoRows(err) {
				continue
			}
			return nil, err
		}
	}

	return holder, nil
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

By default, the ID exporter's output will be JSON of the form:
  [
    { "id": 1 },
    ...
    { "id": n }
  ]

Operations that return a hostname will be JSON of the form:
  [
    { "id": 1, "hostname": "example-1.com" },
    ...
    { "id": n, "hostname": "example-n.com" }
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
	withExampleHostnames := flag.Bool("with-example-hostnames", false, "In addition to IDs, gather an example domain name that corresponds to that ID")
	type config struct {
		ContactExporter struct {
			DB cmd.DBConfig
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

	dbURL, err := cfg.ContactExporter.DB.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbSettings := sa.DbSettings{
		MaxOpenConns: 10,
	}
	dbMap, err := sa.NewDbMap(dbURL, dbSettings)
	cmd.FailOnError(err, "Could not connect to database")

	exporter := idExporter{
		log:   log,
		dbMap: dbMap,
		clk:   cmd.Clock(),
		grace: *grace,
	}

	var results idExporterResults
	if *domainsFile != "" {
		// Gather IDs for the domains listed in the `domainsFile`.
		df, err := ioutil.ReadFile(*domainsFile)
		cmd.FailOnError(err, fmt.Sprintf("Could not read domains file %q", *domainsFile))

		results, err = exporter.findIDsForDomains(strings.Split(string(df), "\n"))
		cmd.FailOnError(err, "Could not find IDs for domains")

	} else if *withExampleHostnames {
		// Gather subscriber IDs and hostnames.
		results, err = exporter.findIDsWithExampleHostnames()
		cmd.FailOnError(err, "Could not find IDs with hostnames")

	} else {
		// Gather only subscriber IDs.
		results, err = exporter.findIDs()
		cmd.FailOnError(err, "Could not find IDs")
	}

	// Write results to file.
	err = results.writeToFile(*outFile)
	cmd.FailOnError(err, fmt.Sprintf("Could not write result to outfile %q", *outFile))
}
