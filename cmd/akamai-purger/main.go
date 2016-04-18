package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/akamai"

	"github.com/letsencrypt/boulder/cmd"
)

func main() {
	app := cli.NewApp()
	app.Name = "akamai-purger"
	app.Usage = "Purge a resource from the Akamai CDN cache"
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
		cli.StringFlag{
			Name:  "url",
			Usage: "URL to purge from CDN",
		},
	}

	app.Action = func(c *cli.Context) {
		configFileName := c.GlobalString("config")
		url := c.GlobalString("url")

		if url == "" || configFileName == "" {
			fmt.Println("Both -url -config (or BOULDER_CONFIG) are required")
			return
		}

		configJSON, err := ioutil.ReadFile(configFileName)
		if err != nil {
			fmt.Printf("Failed to read config file: %s\n", err)
			return
		}

		var config cmd.Config
		err = json.Unmarshal(configJSON, &config)

		// Set up logging
		stats, auditlogger := cmd.StatsAndLogging(config.Statsd, config.Syslog)
		auditlogger.Info(app.Version)

		// AUDIT[ Error Conditions ] 9cc4d537-8534-4970-8665-4b382abe82f3
		defer auditlogger.AuditPanic()

		akamaiClient, err := akamai.NewCachePurgeClient(
			config.OCSPUpdater.AkamaiBaseURL,
			config.OCSPUpdater.AkamaiClientToken,
			config.OCSPUpdater.AkamaiClientSecret,
			config.OCSPUpdater.AkamaiAccessToken,
			config.OCSPUpdater.AkamaiPurgeRetries,
			config.OCSPUpdater.AkamaiPurgeRetryBackoff.Duration,
			auditlogger,
			stats,
		)
		cmd.FailOnError(err, "Failed to create Akamai CachePurgeClient")

		err = akamaiClient.Purge([]string{url})
		cmd.FailOnError(err, "Failed to purge requested resource")
	}

	err := app.Run(os.Args)
	cmd.FailOnError(err, "Failed to run application")
}
