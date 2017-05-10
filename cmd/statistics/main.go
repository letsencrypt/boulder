// Copyright 2016 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"flag"
	"os"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/statistics"
)

type config struct {
	Statistics cmd.StatisticsConfig

	Statsd cmd.StatsdConfig

	Syslog cmd.SyslogConfig
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	outFile := flag.String("outfile", "", "Path to write the JSON output")
	forceStdout := flag.Bool("stdout", false, "Send JSON output to stdout instead of writing to disk; this supercedes --outfile")

	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadJSONFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	stats, logger := cmd.StatsAndLogging(c.Statsd, c.Syslog)

	dbURL, err := c.Statistics.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL, c.Statistics.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Could not connect to database")

	writer := os.Stdout

	if *forceStdout == false && *outFile != "" {
		fd, err := os.Create(*outFile)
		cmd.FailOnError(err, "Could not open outfile for writing")

		defer func() { // May not be called if FailOnError triggers.
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
