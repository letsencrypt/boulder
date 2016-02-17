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
	"strings"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/codegangsta/cli"
	_ "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/go-sql-driver/mysql"
	"github.com/letsencrypt/boulder/sa"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/policy"
)

func main() {
	app := cli.NewApp()
	app.Name = "policy-loader"
	app.Usage = "Loads/dumps rules into/from the policy database"
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
			Name:   "rule-file",
			Value:  "rules.json",
			EnvVar: "BOULDER_POLICY_RULES",
			Usage:  "Path to Boulder policy whitelist and blacklist rule file",
		},
	}

	app.Commands = append(app.Commands, []cli.Command{
		{
			Name:  "dump-rules",
			Usage: "Write out whitelist and blacklist from database to a rule file",
			Action: func(c *cli.Context) {
				padb, ruleFile := setupFromContext(c)
				ruleSet, err := padb.DumpRules()
				cmd.FailOnError(err, "Couldn't retrieve whitelist rules")
				var rules struct {
					Blacklist []string
					Whitelist []string
				}
				for _, r := range ruleSet.Blacklist {
					rules.Blacklist = append(rules.Blacklist, r.Host)
				}
				for _, r := range ruleSet.Whitelist {
					rules.Whitelist = append(rules.Whitelist, r.Host)
				}
				rulesJSON, err := json.Marshal(rules)
				cmd.FailOnError(err, "Couldn't marshal rule list")
				err = ioutil.WriteFile(ruleFile, rulesJSON, os.ModePerm)
				cmd.FailOnError(err, "Failed to write the rule file")
				fmt.Printf("# Saved rule list to %s\n", ruleFile)
			},
		},
		{
			Name:  "load-rules",
			Usage: "Load whitelist and blacklist into database from a rule file",
			Action: func(c *cli.Context) {
				padb, ruleFile := setupFromContext(c)

				rulesJSON, err := ioutil.ReadFile(ruleFile)
				cmd.FailOnError(err, "Couldn't read configuration file")
				rules := policy.RawRuleSet{}
				err = json.Unmarshal(rulesJSON, &rules)
				cmd.FailOnError(err, "Couldn't unmarshal rules list")
				rs := policy.RuleSet{}
				for _, r := range rules.Blacklist {
					rs.Blacklist = append(rs.Blacklist, policy.BlacklistRule{
						Host: strings.ToLower(r),
					})
				}
				for _, r := range rules.Whitelist {
					rs.Whitelist = append(rs.Whitelist, policy.WhitelistRule{
						Host: strings.ToLower(r),
					})
				}

				err = padb.LoadRules(rs)
				cmd.FailOnError(err, "Couldn't load rules")

				fmt.Println("# Loaded whitelist and blacklist into database")
			},
		},
	}...)

	app.Run(os.Args)
}

func setupFromContext(context *cli.Context) (*policy.AuthorityDatabaseImpl, string) {
	configFileName := context.GlobalString("config")
	configJSON, err := ioutil.ReadFile(configFileName)
	cmd.FailOnError(err, "Couldn't read configuration file")
	var c cmd.Config
	err = json.Unmarshal(configJSON, &c)
	cmd.FailOnError(err, "Couldn't unmarshal configuration object")

	dbURL, err := c.PA.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")
	dbMap, err := sa.NewDbMap(dbURL)
	cmd.FailOnError(err, "Failed to create DB map")

	padb, err := policy.NewAuthorityDatabaseImpl(dbMap)
	cmd.FailOnError(err, "Could not connect to PADB")

	ruleFile := context.GlobalString("rule-file")
	if ruleFile == "" {
		fmt.Println("rule-file argument is required")
		os.Exit(1)
	}

	return padb, ruleFile
}
