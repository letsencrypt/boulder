package notmain

import (
	"flag"

	"github.com/honeycombio/beeline-go"

	"github.com/letsencrypt/boulder/cmd"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/nonce"
	noncepb "github.com/letsencrypt/boulder/nonce/proto"
)

type Config struct {
	NonceService struct {
		cmd.ServiceConfig

		MaxUsed     int
		NoncePrefix string

		Syslog  cmd.SyslogConfig
		Beeline cmd.BeelineConfig
	}
}

func main() {
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	prefixOverride := flag.String("prefix", "", "Override the configured nonce prefix")
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	if *grpcAddr != "" {
		c.NonceService.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.NonceService.DebugAddr = *debugAddr
	}
	if *prefixOverride != "" {
		c.NonceService.NoncePrefix = *prefixOverride
	}

	bc, err := c.NonceService.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

	scope, logger := cmd.StatsAndLogging(c.NonceService.Syslog, c.NonceService.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	ns, err := nonce.NewNonceService(scope, c.NonceService.MaxUsed, c.NonceService.NoncePrefix)
	cmd.FailOnError(err, "Failed to initialize nonce service")

	tlsConfig, err := c.NonceService.TLS.Load()
	cmd.FailOnError(err, "tlsConfig config")

	nonceServer := nonce.NewServer(ns)
	start, stop, err := bgrpc.NewServer(c.NonceService.GRPC).Add(
		&noncepb.NonceService_ServiceDesc, nonceServer).Build(tlsConfig, scope, cmd.Clock())
	cmd.FailOnError(err, "Unable to setup nonce service gRPC server")

	go cmd.CatchSignals(logger, stop)
	cmd.FailOnError(start(), "Nonce service gRPC server failed")
}

func init() {
	cmd.RegisterCommand("nonce-service", main)
}
