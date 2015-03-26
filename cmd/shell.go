// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// This package provides utilities that underlie the specific commands.
// The idea is to make the specific command files very small, e.g.:
//
//    func main() {
//      app := cmd.NewAppShell("command-name")
//      app.Action = func(c cmd.Config) {
//        // command logic
//      }
//      app.Run()
//    }
//
// All commands share the same invocation pattern.  They take a single
// parameter "-config", which is the name of a JSON file containing
// the configuration for the app.  This JSON file is unmarshalled into
// a Config object, which is provided to the app.

package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/codegangsta/cli"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/streadway/amqp"
)

// Config stores configuration parameters that applications
// will need.  For simplicity, we just lump them all into
// one struct, and use encoding/json to read it from a file.
//
// Note: NO DEFAULTS are provided.
type Config struct {
	// General
	AMQP struct {
		Server string
		RA     QueuePair
		VA     QueuePair
		SA     QueuePair
		CA     QueuePair
	}

	WFE struct {
		BaseURL       string
		ListenAddress string
	}

	CA struct {
		Server  string
		AuthKey string
		Profile string
	}

	SA struct {
		DBDriver string
		DBName   string
	}

	Syslog struct {
		Network string
		Server  string
		Tag     string
	}
}

type QueuePair struct {
	Client string
	Server string
}

type AppShell struct {
	Action func(Config)
	app    *cli.App
}

func NewAppShell(name string) (shell *AppShell) {
	app := cli.NewApp()

	app.Name = name
	app.Version = "0.0.0"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "config",
			Value:  "config.json",
			EnvVar: "BOULDER_CONFIG",
		},
	}

	return &AppShell{app: app}
}

func (as *AppShell) Run() {
	as.app.Action = func(c *cli.Context) {
		configFileName := c.GlobalString("config")
		configJSON, err := ioutil.ReadFile(configFileName)
		FailOnError(err, "Unable to read config file")

		var config Config
		err = json.Unmarshal(configJSON, &config)
		FailOnError(err, "Failed to read configuration")

		as.Action(config)
	}

	err := as.app.Run(os.Args)
	FailOnError(err, "Failed to run application")
}

// Exit and print error message if we encountered a problem
func FailOnError(err error, msg string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		os.Exit(1)
	}
}

// This is the same as amqpConnect in boulder, but with even
// more aggressive error dropping
func AmqpChannel(url string) (ch *amqp.Channel) {
	conn, err := amqp.Dial(url)
	FailOnError(err, "Unable to connect to AMQP server")

	ch, err = conn.Channel()
	FailOnError(err, "Unable to establish channel to AMQP server")
	return
}

// Start the server and wait around
func RunForever(server *rpc.AmqpRPCServer) {
	forever := make(chan bool)
	server.Start()
	fmt.Fprintf(os.Stderr, "Server running...\n")
	<-forever
}
