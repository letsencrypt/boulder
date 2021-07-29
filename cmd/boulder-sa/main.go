package main

import (
	"flag"
	"os"

	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/honeycombio/beeline-go"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/features"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/sa"
	sapb "github.com/letsencrypt/boulder/sa/proto"
)

type config struct {
	SA struct {
		cmd.ServiceConfig
		DB         cmd.DBConfig
		ReadOnlyDB cmd.DBConfig

		Features map[string]bool

		// Max simultaneous SQL queries caused by a single RPC.
		ParallelismPerRPC int
	}

	Syslog  cmd.SyslogConfig
	Beeline cmd.BeelineConfig
}

func main() {
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
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

	if *grpcAddr != "" {
		c.SA.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.SA.DebugAddr = *debugAddr
	}

	bc, err := c.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

	scope, logger := cmd.StatsAndLogging(c.Syslog, c.SA.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	saConf := c.SA
	saDbSettings := sa.DbSettings{
		MaxOpenConns:    saConf.DB.MaxOpenConns,
		MaxIdleConns:    saConf.DB.MaxIdleConns,
		ConnMaxLifetime: saConf.DB.ConnMaxLifetime.Duration,
		ConnMaxIdleTime: saConf.DB.ConnMaxIdleTime.Duration,
	}

	dbURL, err := saConf.DB.URL()
	cmd.FailOnError(err, "Couldn't load DB URL")

	dbMap, err := sa.NewDbMap(dbURL, saDbSettings)
	cmd.FailOnError(err, "Couldn't connect to SA database")

	dbAddr, dbUser, err := saConf.DB.DSNAddressAndUser()
	cmd.FailOnError(err, "Could not determine address or user of DB DSN")

	// Collect and periodically report DB metrics using the DBMap and prometheus scope.
	sa.InitDBMetrics(dbMap, scope, saDbSettings, dbAddr, dbUser)

	var dbReadOnlyMap *db.WrappedMap

	dbReadOnlyURL, err := saConf.ReadOnlyDB.URL()
	cmd.FailOnError(err, "Couldn't load read-only DB URL")
	if dbReadOnlyURL == "" {
		dbReadOnlyMap = dbMap
	} else {
		roDbSettings := sa.DbSettings{
			MaxOpenConns:    saConf.ReadOnlyDB.MaxOpenConns,
			MaxIdleConns:    saConf.ReadOnlyDB.MaxIdleConns,
			ConnMaxLifetime: saConf.ReadOnlyDB.ConnMaxLifetime.Duration,
			ConnMaxIdleTime: saConf.ReadOnlyDB.ConnMaxIdleTime.Duration}

		dbReadOnlyMap, err = sa.NewDbMap(dbReadOnlyURL, roDbSettings)
		cmd.FailOnError(err, "Could not connect to read-only database")

		dbReadOnlyAddr, dbReadOnlyUser, err := saConf.ReadOnlyDB.DSNAddressAndUser()
		cmd.FailOnError(err, "Could not determine address or user of read-only DB DSN")

		sa.InitDBMetrics(dbReadOnlyMap, scope, roDbSettings, dbReadOnlyAddr, dbReadOnlyUser)
	}

	clk := cmd.Clock()

	parallel := saConf.ParallelismPerRPC
	if parallel < 1 {
		parallel = 1
	}
	sai, err := sa.NewSQLStorageAuthority(dbMap, dbReadOnlyMap, clk, logger, scope, parallel)
	cmd.FailOnError(err, "Failed to create SA impl")

	tls, err := c.SA.TLS.Load()
	cmd.FailOnError(err, "TLS config")
	serverMetrics := bgrpc.NewServerMetrics(scope)
	grpcSrv, listener, err := bgrpc.NewServer(c.SA.GRPC, tls, serverMetrics, clk, bgrpc.NoCancelInterceptor)
	cmd.FailOnError(err, "Unable to setup SA gRPC server")
	gw := bgrpc.NewStorageAuthorityServer(sai)
	sapb.RegisterStorageAuthorityServer(grpcSrv, gw)
	hs := health.NewServer()
	healthpb.RegisterHealthServer(grpcSrv, hs)

	go cmd.CatchSignals(logger, func() {
		hs.Shutdown()
		grpcSrv.GracefulStop()
	})

	err = cmd.FilterShutdownErrors(grpcSrv.Serve(listener))
	cmd.FailOnError(err, "SA gRPC service failed")
}
