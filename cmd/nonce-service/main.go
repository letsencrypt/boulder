package notmain

import (
	"flag"
	"fmt"
	"net"

	"github.com/honeycombio/beeline-go"

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
		NoncePrefix string

		// UseDerivablePrefix indicates whether or not to use a nonce prefix
		// derived from the SHA256 of the host's IP address and a salt.
		//
		// TODO(#6610): Remove once we've moved to derivable prefixes by
		// default.
		UseDerivablePrefix bool
		// Salt is the path to a file containing the salt used to derive a nonce
		// prefix. This is only used if UseDerivablePrefix is true.
		//
		// TODO(#6610): Edit this comment once we've moved to derivable prefixes
		// by default.
		Salt cmd.PasswordConfig

		Syslog  cmd.SyslogConfig
		Beeline cmd.BeelineConfig
	}
}

func derivePrefix(salt string, grpcAddr string) (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	host, port, err := net.SplitHostPort(grpcAddr)
	if err != nil {
		return "", fmt.Errorf("parsing listen address: %w", err)
	}

	// If the configuration specifies a host and port, we should use it to
	// derive the nonce prefix.
	if host != "" && port != "" {
		localAddr := host + ":" + port
		return nonce.DerivePrefix(localAddr, salt), nil
	}

	// Otherwise, we should use the only non-loopback IPv4 address we find on
	// the system.
	var interfaces []string
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if ok {
			if !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				interfaces = append(interfaces, ipnet.IP.String())
			}
		}
	}
	if len(interfaces) == 0 {
		// This should never happen.
		return "", fmt.Errorf("checking for interface: no interfaces found")
	}
	if len(interfaces) > 1 {
		// This should (ideally) never happen.
		return "", fmt.Errorf("checking for interface: multiple interfaces found")
	}
	localAddr := interfaces[0] + ":" + port
	return nonce.DerivePrefix(localAddr, salt), nil
}

func main() {
	grpcAddr := flag.String("addr", "", "gRPC listen address override")
	debugAddr := flag.String("debug-addr", "", "Debug server address override")
	prefixOverride := flag.String("prefix", "", "Override the configured nonce prefix")
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()

	var c Config
	conf := c.NonceService
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	if *grpcAddr != "" {
		conf.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		conf.DebugAddr = *debugAddr
	}
	if *prefixOverride != "" {
		conf.NoncePrefix = *prefixOverride
	}
	// TODO(#6610): Remove once we've moved to derivable prefixes by default.
	if conf.NoncePrefix != "" && conf.UseDerivablePrefix {
		cmd.Fail("Cannot set both 'noncePrefix' and 'useDerivablePrefix'")
	}
	// TODO(#6610): Remove once we've moved to derivable prefixes by default.
	if len(conf.NoncePrefix) != nonce.PrefixLenDepracated {
		cmd.Fail(
			fmt.Sprintf("'noncePrefix' must be %d characters, %q has a length of %d",
				nonce.PrefixLenDepracated,
				conf.NoncePrefix,
				len(conf.NoncePrefix),
			),
		)
	}
	// TODO(#6610): Remove once we've moved to derivable prefixes by default.
	if conf.UseDerivablePrefix && conf.Salt.PasswordFile == "" {
		cmd.Fail("Cannot set 'salt' without 'useDerivablePrefix'")
	}

	if conf.UseDerivablePrefix && conf.Salt.PasswordFile != "" {
		salt, err := conf.Salt.Pass()
		cmd.FailOnError(err, "Failed to load 'salt' file.")
		conf.NoncePrefix, err = derivePrefix(salt, conf.GRPC.Address)
		cmd.FailOnError(err, "Failed to derive nonce prefix")
	}

	bc, err := conf.Beeline.Load()
	cmd.FailOnError(err, "Failed to load Beeline config")
	beeline.Init(bc)
	defer beeline.Close()

	scope, logger := cmd.StatsAndLogging(conf.Syslog, conf.DebugAddr)
	defer logger.AuditPanic()
	logger.Info(cmd.VersionString())

	ns, err := nonce.NewNonceService(scope, conf.MaxUsed, conf.NoncePrefix)
	cmd.FailOnError(err, "Failed to initialize nonce service")

	tlsConfig, err := conf.TLS.Load()
	cmd.FailOnError(err, "tlsConfig config")

	nonceServer := nonce.NewServer(ns)
	start, stop, err := bgrpc.NewServer(conf.GRPC).Add(
		&noncepb.NonceService_ServiceDesc, nonceServer).Build(tlsConfig, scope, cmd.Clock())
	cmd.FailOnError(err, "Unable to setup nonce service gRPC server")

	go cmd.CatchSignals(logger, stop)
	cmd.FailOnError(start(), "Nonce service gRPC server failed")
}

func init() {
	cmd.RegisterCommand("nonce-service", main)
}
