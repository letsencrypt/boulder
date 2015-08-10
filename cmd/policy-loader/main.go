// Copyright 2015 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	// Load both drivers to allow configuring either
	"github.com/cactus/go-statsd-client/statsd"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"
	"github.com/letsencrypt/boulder/core"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/policy"
)

func setupContext(context *cli.Context) (core.PolicyAuthorityDatabase, *blog.AuditLogger) {
	configFileName := context.GlobalString("config")
	configJSON, err := ioutil.ReadFile(configFileName)
	cmd.FailOnError(err, "Couldn't read configuration file")
	var c cmd.Config
	err = json.Unmarshal(configJSON, &c)
	cmd.FailOnError(err, "Couldn't unmarshal configuration object")
	// Set up logging
	stats, err := statsd.NewClient(c.Statsd.Server, c.Statsd.Prefix)
	cmd.FailOnError(err, "Couldn't connect to statsd")
	logger, err := blog.Dial(c.Syslog.Network, c.Syslog.Server, c.Syslog.Tag, stats)
	cmd.FailOnError(err, "Could not connect to Syslog")

	padb, err := policy.NewPolicyAuthorityDatabaseImpl(c.Common.PolicyDBDriver, c.Common.PolicyDBConnect)
	cmd.FailOnError(err, "Could not connect to PADB")
	return padb, logger
}

func main() {
	app := cli.NewApp()
	app.Name = "policy-loader"
	app.Version = "0.0.1"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Value:  "config.json",
			EnvVar: "BOULDER_CONFIG",
			Usage:  "Path to Boulder JSON configuration file",
		},
	}

	app.Commands = append(app.Commands, []cli.Command{
		cli.Command{
			Name:  "view-whitelist",
			Usage: "Print whitelist",
			Action: func(c *cli.Context) {
				padb, _ := setupContext(c)
				rules, err := padb.GetRules("whitelist")
				cmd.FailOnError(err, "Couldn't retrieve whitelist rules")
				fmt.Println("# Domain whitelist")
				for _, rule := range rules {
					fmt.Println(rule)
				}
			},
		},
		cli.Command{
			Name:  "view-blacklist",
			Usage: "Print blacklist",
			Action: func(c *cli.Context) {
				padb, _ := setupContext(c)
				rules, err := padb.GetRules("blacklist")
				cmd.FailOnError(err, "Couldn't retrieve blacklist rules")
				fmt.Println("# Domain blacklist")
				for _, rule := range rules {
					fmt.Println(rule)
				}
			},
		},
		cli.Command{
			Name:  "delete-rule",
			Usage: "Delete a rule",
			Action: func(c *cli.Context) {
				padb, _ := setupContext(c)
				rule := c.Args().First()
				if rule == "" {
					fmt.Fprintf(os.Stderr, "No rule provided\n")
					os.Exit(1)
				}
				err := padb.DeleteRule(rule)
				cmd.FailOnError(err, "Couldn't delete rule")
				fmt.Printf("Deleted rule \"%s\"\n", rule)
			},
		},
		cli.Command{
			Name:  "add-whitelist-rule",
			Usage: "Add a rule to the whtielist",
			Action: func(c *cli.Context) {
				padb, _ := setupContext(c)
				rule := c.Args().First()
				if rule == "" {
					fmt.Fprintf(os.Stderr, "No rule provided\n")
					os.Exit(1)
				}
				err := padb.AddRule(rule, "whitelist")
				cmd.FailOnError(err, "Couldn't add rule to whitelist")
				fmt.Printf("Added rule \"%s\" to whitelist\n", rule)
			},
		},
		cli.Command{
			Name:  "add-blacklist-rule",
			Usage: "Add a rule to the blacklist",
			Action: func(c *cli.Context) {
				padb, _ := setupContext(c)
				rule := c.Args().First()
				if rule == "" {
					fmt.Fprintf(os.Stderr, "No rule provided\n")
					os.Exit(1)
				}
				err := padb.AddRule(rule, "blacklist")
				cmd.FailOnError(err, "Couldn't add rule to blacklist")
				fmt.Printf("Added rule \"%s\" to blacklist\n", rule)
			},
		},
	}...)

	app.Run(os.Args)
}
