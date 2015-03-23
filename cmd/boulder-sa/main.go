// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	// Load both drivers to allow configuring either
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

func main() {
	app := cmd.NewAppShell("boulder-sa")
	app.Action = func(c cmd.Config) {
		ch := cmd.AmqpChannel(c.AMQP.Server)

		sai, err := sa.NewSQLStorageAuthority(c.SA.DBDriver, c.SA.DBName)
		cmd.FailOnError(err, "Failed to create SA impl")

		sas := rpc.NewStorageAuthorityServer(c.AMQP.SA.Server, ch, sai)
		cmd.RunForever(sas)
	}

	app.Run()
}
