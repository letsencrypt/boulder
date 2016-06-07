package main

import (
	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

func main() {
	app := cmd.NewAppShell("boulder-sa", "Handles SQL operations")
	app.Action = func(c cmd.Config, stats metrics.Statter, logger blog.Logger) {
		saConf := c.SA
		go cmd.DebugServer(saConf.DebugAddr)

		dbURL, err := saConf.DBConfig.URL()
		cmd.FailOnError(err, "Couldn't load DB URL")
		dbMap, err := sa.NewDbMap(dbURL, saConf.DBConfig.MaxDBConns)
		cmd.FailOnError(err, "Couldn't connect to SA database")
		go sa.ReportDbConnCount(dbMap, metrics.NewStatsdScope(stats, "SA"))

		sai, err := sa.NewSQLStorageAuthority(dbMap, clock.Default(), logger)
		cmd.FailOnError(err, "Failed to create SA impl")

		go cmd.ProfileCmd("SA", stats)

		amqpConf := saConf.AMQP
		sas, err := rpc.NewAmqpRPCServer(amqpConf, c.SA.MaxConcurrentRPCServerRequests, stats, logger)
		cmd.FailOnError(err, "Unable to create SA RPC server")
		err = rpc.NewStorageAuthorityServer(sas, sai)
		cmd.FailOnError(err, "Unable to setup SA RPC server")

		err = sas.Start(amqpConf)
		cmd.FailOnError(err, "Unable to run SA RPC server")
	}

	app.Run()
}
