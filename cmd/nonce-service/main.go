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
		// TODO(#6610): Remove once we've moved to derivable prefixes by
		// default.
		NoncePrefix string `validate:"excluded_with=UseDerivablePrefix,omitempty,len=4"`

		// UseDerivablePrefix indicates whether to use a nonce prefix derived
		// from the gRPC listening address. If this is false, the nonce prefix
		// will be the value of the NoncePrefix field. If this is true, the
		// NoncePrefixKey field is required.
		//
		// TODO(#6610): Remove once we've moved to derivable prefixes by
		// default.
		UseDerivablePrefix bool `validate:"excluded_with=NoncePrefix"`

		// NoncePrefixKey is a secret used for deriving the prefix of each nonce
		// instance. It should contain 256 bits (32 bytes) of random data to be
		// suitable as an HMAC-SHA256 key (e.g. the output of `openssl rand -hex
		// 32`). In a multi-DC deployment this value should be the same across
		// all boulder-wfe and nonce-service instances. This is only used if
		// UseDerivablePrefix is true.
		//
		// TODO(#6610): Edit this comment once we've moved to derivable prefixes
		// by default.
		NoncePrefixKey cmd.PasswordConfig `validate:"excluded_with=NoncePrefix,structonly"`

		Syslog        cmd.SyslogConfig
		OpenTelemetry cmd.OpenTelemetryConfig
	}
}

func derivePrefix(key string, grpcAddr string) (string, error) {
	host, port, err := net.SplitHostPort(grpcAddr)
	if err != nil {
		return "", fmt.Errorf("parsing gRPC listen address: %w", err)
	}
	if host != "" && port != "" {
		hostIP := net.ParseIP(host)
		if hostIP == nil {
			return "", fmt.Errorf("parsing IP from gRPC listen address: %w", err)
		}
	}
	return nonce.DerivePrefix(grpcAddr, key), nil
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

	var c Config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	if *grpcAddr != "" {
		c.NonceService.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.NonceService.DebugAddr = *debugAddr
	}

	// TODO(#6610): Remove once we've moved to derivable prefixes by default.
	if c.NonceService.NoncePrefix != "" && c.NonceService.UseDerivablePrefix {
		cmd.Fail("Cannot set both 'noncePrefix' and 'useDerivablePrefix'")
	}

	// TODO(#6610): Remove once we've moved to derivable prefixes by default.
	if c.NonceService.UseDerivablePrefix && c.NonceService.NoncePrefixKey.PasswordFile == "" {
		cmd.Fail("Cannot set 'noncePrefixKey' without 'useDerivablePrefix'")
	}

	if c.NonceService.UseDerivablePrefix && c.NonceService.NoncePrefixKey.PasswordFile != "" {
		key, err := c.NonceService.NoncePrefixKey.Pass()
		cmd.FailOnError(err, "Failed to load 'noncePrefixKey' file.")
		c.NonceService.NoncePrefix, err = derivePrefix(key, c.NonceService.GRPC.Address)
		cmd.FailOnError(err, "Failed to derive nonce prefix")
	}

	scope, logger, oTelShutdown := cmd.StatsAndLogging(c.NonceService.Syslog, c.NonceService.OpenTelemetry, c.NonceService.DebugAddr)
	defer oTelShutdown(context.Background())
	logger.Info(cmd.VersionString())

	ns, err := nonce.NewNonceService(scope, c.NonceService.MaxUsed, c.NonceService.NoncePrefix)
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
