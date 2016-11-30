package main

import (
	"flag"
	"net"
	"os"

	"github.com/jmhodges/clock"
	"google.golang.org/grpc"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/rpc"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

const clientName = "SA"

type config struct {
	SA struct {
		cmd.ServiceConfig
		cmd.DBConfig

		MaxConcurrentRPCServerRequests int64

		Features map[string]bool
	}

	Statsd cmd.StatsdConfig

	Syslog cmd.SyslogConfig
}

func main() {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	err = features.Set(c.SA.Features)
	cmd.FailOnError(err, "Failed to set feature flags")

	stats, logger := cmd.StatsAndLogging(c.Statsd, c.Syslog)
	scope := metrics.NewStatsdScope(stats, "SA")
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString(clientName))

	saConf := c.SA

	dbURL, err := saConf.DBConfig.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")

	dbMap, err := sa.NewDbMap(dbURL, saConf.DBConfig.MaxDBConns)
	cmd.FailOnError(err, "Couldn't connect to SA database")

	sa.SetSQLDebug(dbMap, logger)

	go sa.ReportDbConnCount(dbMap, scope)

	sai, err := sa.NewSQLStorageAuthority(dbMap, clock.Default(), logger)
	cmd.FailOnError(err, "Failed to create SA impl")

	var grpcSrv *grpc.Server
	if c.SA.GRPC != nil {
		var listener net.Listener
		grpcSrv, listener, err = bgrpc.NewServer(c.SA.GRPC, scope)
		cmd.FailOnError(err, "Unable to setup SA gRPC server")
		gw := bgrpc.NewStorageAuthorityServer(sai)
		sapb.RegisterStorageAuthorityServer(grpcSrv, gw)
		go func() {
			err = grpcSrv.Serve(listener)
			cmd.FailOnError(err, "SA gRPC service failed")
		}()
	}

	amqpConf := saConf.AMQP
	sas, err := rpc.NewAmqpRPCServer(amqpConf, c.SA.MaxConcurrentRPCServerRequests, scope, logger)
	cmd.FailOnError(err, "Unable to create SA RPC server")

	go cmd.CatchSignals(logger, func() {
		sas.Stop()
		if grpcSrv != nil {
			grpcSrv.GracefulStop()
		}
	})

	err = rpc.NewStorageAuthorityServer(sas, sai)
	cmd.FailOnError(err, "Unable to setup SA RPC server")

	go cmd.DebugServer(c.SA.DebugAddr)
	go cmd.ProfileCmd(scope)

	err = sas.Start(amqpConf)
	cmd.FailOnError(err, "Unable to run SA RPC server")
}
