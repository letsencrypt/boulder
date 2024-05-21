package notmain

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/letsencrypt/boulder/cmd"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/nonce"
	noncepb "github.com/letsencrypt/boulder/nonce/proto"
)

type Config struct {
	NonceService struct {
		cmd.ServiceConfig

		MaxUsed int

		// UseDerivablePrefix indicates whether to use a nonce prefix derived
		// from the gRPC listening address. If this is false, the nonce prefix
		// will be the value of the NoncePrefix field. If this is true, the
		// NoncePrefixKey field is required.
		// TODO(#6610): Remove this.
		//
		// Deprecated: this value is ignored, and treated as though it is always true.
		UseDerivablePrefix bool `validate:"-"`

		// NoncePrefixKey is a secret used for deriving the prefix of each nonce
		// instance. It should contain 256 bits (32 bytes) of random data to be
		// suitable as an HMAC-SHA256 key (e.g. the output of `openssl rand -hex
		// 32`). In a multi-DC deployment this value should be the same across
		// all boulder-wfe and nonce-service instances.
		NoncePrefixKey cmd.PasswordConfig `validate:"required"`

		Syslog        cmd.SyslogConfig
		OpenTelemetry cmd.OpenTelemetryConfig
	}
}

func derivePrefix(key string, grpcAddr string) (string, error) {
	host, port, err := net.SplitHostPort(grpcAddr)
	if err != nil {
		return "", fmt.Errorf("parsing gRPC listen address: %w", err)
	}
	if host == "" {
		return "", fmt.Errorf("nonce service gRPC address must include an IP address: got %q", grpcAddr)
	}
	if host != "" && port != "" {
		hostIP := net.ParseIP(host)
		if hostIP == nil {
			return "", fmt.Errorf("gRPC address host part was not an IP address")
		}
		if hostIP.IsUnspecified() {
			return "", fmt.Errorf("nonce service gRPC address must be a specific IP address: got %q", grpcAddr)
		}
	}
	return nonce.DerivePrefix(grpcAddr, key), nil
}

func main() {
	grpcAddr := flag.String("addr", "", "gRPC listen address override. Also used to derive the nonce prefix.")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()

	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	if *grpcAddr != "" {
		c.NonceService.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.NonceService.DebugAddr = *debugAddr
	}

	if c.NonceService.NoncePrefixKey.PasswordFile == "" {
		cmd.Fail("NoncePrefixKey PasswordFile must be set")
	}

	key, err := c.NonceService.NoncePrefixKey.Pass()
	cmd.FailOnError(err, "Failed to load 'noncePrefixKey' file.")
	noncePrefix, err := derivePrefix(key, c.NonceService.GRPC.Address)
	cmd.FailOnError(err, "Failed to derive nonce prefix")

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.NonceService.Syslog, c.NonceService.OpenTelemetry, c.NonceService.DebugAddr)
	defer oTelShutdown(context.Background())
	logger.Info(cmd.VersionString())

	ns, err := nonce.NewNonceService(scope, c.NonceService.MaxUsed, noncePrefix)
	cmd.FailOnError(err, "Failed to initialize nonce service")

	tlsConfig, err := c.NonceService.TLS.Load(scope)
	cmd.FailOnError(err, "tlsConfig config")

	nonceServer := nonce.NewServer(ns)
	start, err := bgrpc.NewServer(c.NonceService.GRPC, logger).Add(
		&noncepb.NonceService_ServiceDesc, nonceServer).Build(tlsConfig, scope, cmd.Clock())
	cmd.FailOnError(err, "Unable to setup nonce service gRPC server")

	cmd.FailOnError(start(), "Nonce service gRPC server failed")
}

func init() {
	cmd.RegisterCommand("nonce-service", main, &cmd.ConfigValidator{Config: &Config{}})
}
