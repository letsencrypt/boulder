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

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/mattn/go-sqlite3"
	"github.com/letsencrypt/boulder/sa"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/policy"
)

func setupContext(context *cli.Context) (*policy.PolicyAuthorityDatabaseImpl, string) {
	configFileName := context.GlobalString("config")
	configJSON, err := ioutil.ReadFile(configFileName)
	cmd.FailOnError(err, "Couldn't read configuration file")
	var c cmd.Config
	err = json.Unmarshal(configJSON, &c)
	cmd.FailOnError(err, "Couldn't unmarshal configuration object")

	dbMap, err := sa.NewDbMap(c.PA.DBConnect)
	cmd.FailOnError(err, "Failed to create DB map")

	padb, err := policy.NewPolicyAuthorityDatabaseImpl(dbMap)
	cmd.FailOnError(err, "Could not connect to PADB")
	return padb, context.GlobalString("rule-file")
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
		cli.StringFlag{
			Name:   "rule-file",
			Value:  "rules.json",
			EnvVar: "BOULDER_POLICY_RULES",
			Usage:  "Path to Boulder policy whitelist and blacklist rule file",
		},
	}

	app.Commands = append(app.Commands, []cli.Command{
		cli.Command{
			Name:  "dump-rules",
			Usage: "Write out whitelist and blacklist from database to a rule file",
			Action: func(c *cli.Context) {
				padb, ruleFile := setupContext(c)
				rules, err := padb.DumpRules()
				cmd.FailOnError(err, "Couldn't retrieve whitelist rules")
				rulesJSON, err := json.Marshal(rules)
				cmd.FailOnError(err, "Couldn't marshal rule list")
				ioutil.WriteFile(ruleFile, rulesJSON, os.ModePerm)
				fmt.Printf("# Saved rule list to %s\n", ruleFile)
			},
		},
		cli.Command{
			Name:  "load-rules",
			Usage: "Load whitelist and blacklist into database from a rule file",
			Action: func(c *cli.Context) {
				padb, ruleFile := setupContext(c)

				rulesJSON, err := ioutil.ReadFile(ruleFile)
				cmd.FailOnError(err, "Couldn't read configuration file")
				var r []policy.DomainRule
				err = json.Unmarshal(rulesJSON, &r)
				cmd.FailOnError(err, "Couldn't unmarshal rules list")

				err = padb.LoadRules(r)
				cmd.FailOnError(err, "Couldn't load rules")

				fmt.Println("# Loaded whitelist and blacklist into database")
			},
		},
	}...)

	app.Run(os.Args)
}
