// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"os"

	"github.com/codegangsta/cli"
	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/statistics"
)

func main() {
	app := cmd.NewAppShell("statistics", "Generates statistics about Boulder")

	app.App.Flags = append(app.App.Flags, cli.StringFlag{
		Name:   "outfile",
		EnvVar: "OUTFILE",
		Usage:  "Path to write the JSON output",
	}, cli.BoolFlag{
		Name:  "stdout",
		Usage: "Send JSON output to stdout instead of writing to disk",
	})

	app.Config = func(c *cli.Context, config cmd.Config) cmd.Config {
		if c.GlobalString("outfile") != "" {
			config.Statistics.OutputPath = c.GlobalString("outfile")
		}
		if c.GlobalBool("stdout") {
			config.Statistics.OutputPath = ""
		}
		return config
	}

	app.Action = func(c cmd.Config, stats metrics.Statter, logger blog.Logger) {
		// Configure DB
		dbURL, err := c.Statistics.DBConfig.URL()
		cmd.FailOnError(err, "Couldn't load DB URL")
		dbMap, err := sa.NewDbMap(dbURL, c.Statistics.DBConfig.MaxDBConns)
		cmd.FailOnError(err, "Could not connect to database")

		writer := os.Stdout

		if c.Statistics.OutputPath != "" {
			fd, err := os.Create(c.Statistics.OutputPath)
			cmd.FailOnError(err, "Could not open outfile for writing")

			defer func() {
				err := fd.Close()
				cmd.FailOnError(err, "Could not close outfile")
			}()
			writer = fd
		}

		dbstats, err := statistics.NewDBStatsEngine(dbMap, stats, clock.Default(), c.Statistics.TimeWindow, writer, logger)
		cmd.FailOnError(err, "Could not construct engine")
		err = dbstats.Calculate()
		cmd.FailOnError(err, "Could not process statistics")
	}

	app.Run()
}
