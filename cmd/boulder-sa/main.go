package main

import (
	"flag"
	"os"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
)

const clientName = "SA"

type config struct {
	SA struct {
		cmd.ServiceConfig
		cmd.DBConfig

		MaxConcurrentRPCServerRequests int64
	}

	cmd.StatsdConfig

	cmd.SyslogConfig
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var cfg config
	err := cmd.ReadJSONFile(*configFile, &cfg)
	if err != nil {
		cmd.FailOnError(err, "Reading JSON config file into config structure")
	}

	go cmd.DebugServer(cfg.SA.DebugAddr)

	dbURL, err := cfg.SA.DBConfig.URL()
	if err != nil {
		cmd.FailOnError(err, "Couldn't load DB URL")
	}

	dbMap, err := sa.NewDbMap(dbURL, cfg.SA.DBConfig.MaxDBConns)
	if err != nil {
		cmd.FailOnError(err, "Couldn't connect to SA database")
	}

	stats, logger := cmd.StatsAndLogging(cfg.StatsdConfig, cfg.SyslogConfig)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString(clientName))

	go sa.ReportDbConnCount(dbMap, metrics.NewStatsdScope(stats, "SA"))

	sai, err := sa.NewSQLStorageAuthority(dbMap, clock.Default(), logger)
	cmd.FailOnError(err, "Failed to create SA impl")

	go cmd.ProfileCmd("SA", stats)

	sas, err := rpc.NewAmqpRPCServer(cfg.SA.AMQP, cfg.SA.MaxConcurrentRPCServerRequests, stats, logger)
	cmd.FailOnError(err, "Unable to create SA RPC server")

	err = rpc.NewStorageAuthorityServer(sas, sai)
	cmd.FailOnError(err, "Unable to setup SA RPC server")

	err = sas.Start(cfg.SA.AMQP)
	cmd.FailOnError(err, "Unable to run SA RPC server")
}
