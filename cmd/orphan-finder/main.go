package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/rpc"
)

type config struct {
	AMQP   cmd.AMQPConfig
	Statsd cmd.StatsdConfig
	Syslog cmd.SyslogConfig
}

var (
	b64derOrphan = regexp.MustCompile(`b64der=\[([a-zA-Z0-9+/]+)\]`)
	regOrphan    = regexp.MustCompile(`regID=\[(\d+)\]`)
)

func checkDER(sai core.StorageAuthority, der []byte) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("Failed to parse DER: %s", err)
	}
	_, err = sai.GetCertificate(core.SerialToString(cert.SerialNumber))
	if err == nil {
		return fmt.Errorf("Existing certificate found with serial %s", core.SerialToString(cert.SerialNumber))
	}
	if _, ok := err.(core.NotFoundError); ok {
		return nil
	}
	return fmt.Errorf("Existing certificate lookup failed: %s", err)
}

func parseLogLine(sa core.StorageAuthority, logger *blog.AuditLogger, line string) (found bool, added bool) {
	if !strings.Contains(line, "b64der=") {
		return false, false
	}
	derStr := b64derOrphan.FindStringSubmatch(line)
	if len(derStr) <= 1 {
		logger.Err(fmt.Sprintf("b64der variable is empty, [%s]", line))
		return true, false
	}
	der, err := base64.StdEncoding.DecodeString(derStr[1])
	if err != nil {
		logger.Err(fmt.Sprintf("Couldn't decode b64: %s, [%s]", err, line))
		return true, false
	}
	err = checkDER(sa, der)
	if err != nil {
		logger.Err(fmt.Sprintf("%s, [%s]", err, line))
		return true, false
	}
	// extract the regID
	regStr := regOrphan.FindStringSubmatch(line)
	if len(regStr) <= 1 {
		logger.Err(fmt.Sprintf("regID variable is empty, [%s]", line))
		return true, false
	}
	regID, err := strconv.Atoi(regStr[1])
	if err != nil {
		logger.Err(fmt.Sprintf("Couldn't parse regID: %s, [%s]", err, line))
		return true, false
	}
	_, err = sa.AddCertificate(der, int64(regID))
	if err != nil {
		logger.Err(fmt.Sprintf("Failed to store certificate: %s, [%s]", err, line))
		return true, false
	}
	return true, true
}

func setup(c *cli.Context) (statsd.Statter, *blog.AuditLogger, *rpc.StorageAuthorityClient) {
	configJSON, err := ioutil.ReadFile(c.GlobalString("config"))
	cmd.FailOnError(err, "Failed to read config file")
	var conf config
	err = json.Unmarshal(configJSON, &conf)
	cmd.FailOnError(err, "Failed to parse config file")
	stats, logger := cmd.StatsAndLogging(conf.Statsd, conf.Syslog)
	sa, err := rpc.NewStorageAuthorityClient("orphan-finder", &conf.AMQP, stats)
	cmd.FailOnError(err, "Failed to create SA client")
	return stats, logger, sa
}

func main() {
	app := cli.NewApp()
	app.Name = "orphan-finder"
	app.Usage = "Reads orphaned certificates from a boulder-ca log or a der file and add them to the database"
	app.Version = cmd.Version()
	app.Author = "Boulder contributors"
	app.Email = "ca-dev@letsencrypt.org"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Value:  "config.json",
			EnvVar: "BOULDER_CONFIG",
			Usage:  "Path to Boulder JSON configuration file",
		},
	}

	app.Commands = []cli.Command{
		{
			Name:  "parse-ca-log",
			Usage: "Parses boulder-ca logs to add multiple orphaned certificates",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "log-file",
					Usage: "Path to boulder-ca log file to parse",
				},
			},
			Action: func(c *cli.Context) {
				stats, logger, sa := setup(c)
				logPath := c.String("log-file")
				if logPath == "" {
					fmt.Println("log file path must be provided")
					os.Exit(1)
				}

				logData, err := ioutil.ReadFile(logPath)
				cmd.FailOnError(err, "Failed to read log file")

				orphansFound := int64(0)
				orphansAdded := int64(0)
				for _, line := range strings.Split(string(logData), "\n") {
					found, added := parseLogLine(sa, logger, line)
					if found {
						orphansFound++
						if added {
							orphansAdded++
						}
					}
				}
				logger.Info(fmt.Sprintf("Found %d orphans and added %d to the database\n", orphansFound, orphansAdded))
				stats.Inc("orphaned-certificates.found", orphansFound, 1.0)
				stats.Inc("orphaned-certificates.added", orphansAdded, 1.0)
				stats.Inc("orphaned-certificates.adding-failed", orphansFound-orphansAdded, 1.0)
			},
		},
		{
			Name:  "parse-der",
			Usage: "Parses a single orphaned DER certificate file and adds it to the database",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "der-file",
					Usage: "Path to DER certificate file",
				},
				cli.IntFlag{
					Name:  "regID",
					Usage: "Registration ID of user who requested the certificate",
				},
			},
			Action: func(c *cli.Context) {
				_, _, sa := setup(c)
				derPath := c.String("der-file")
				if derPath == "" {
					fmt.Println("der file path must be provided")
					os.Exit(1)
				}
				regID := c.Int("regID")
				if regID == 0 {
					fmt.Println("--regID must be non-zero")
					os.Exit(1)
				}
				der, err := ioutil.ReadFile(derPath)
				cmd.FailOnError(err, "Failed to read DER file")
				err = checkDER(sa, der)
				cmd.FailOnError(err, "Pre-AddCertificate checks failed")
				_, err = sa.AddCertificate(der, int64(regID))
				cmd.FailOnError(err, "Failed to add certificate to database")
			},
		},
	}

	app.Run(os.Args)
}
