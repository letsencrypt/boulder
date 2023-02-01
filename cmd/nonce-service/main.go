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
		// PrefixSalt is the path to a file containing the salt used to derive
		// the nonce prefix. This is only used if UseDerivablePrefix is true.
		//
		// TODO(#6610): Edit this comment once we've moved to derivable prefixes
		// by default.
		PrefixSalt cmd.PasswordConfig

		Syslog  cmd.SyslogConfig
		Beeline cmd.BeelineConfig
	}
}

func derivePrefix(salt string, grpcAddr string) (string, error) {
	// If the configuration specifies an IP address and port, we should use it
	// to derive the nonce prefix.
	host, port, err := net.SplitHostPort(grpcAddr)
	if err != nil {
		return "", fmt.Errorf("parsing gRPC listen address: %w", err)
	}
	if host != "" && port != "" {
		hostIP := net.ParseIP(host)
		if hostIP != nil && (hostIP.To4() != nil || hostIP.To16() != nil) {
			return nonce.DerivePrefix(grpcAddr, salt), nil
		}
	}

	// Otherwise, we should use the only non-loopback interface with an IP
	// address we find on the system and the port passed in the gRPC
	// configuration. Technically, this could still fail if the system has
	// multiple non-loopback interfaces, but that should be exceedingly rare.
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	var interfaces []string
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if ok {
			if !ipnet.IP.IsLoopback() && (ipnet.IP.To4() != nil || ipnet.IP.To16() != nil) {
				interfaces = append(interfaces, ipnet.IP.String())
			}
		}
	}
	if len(interfaces) == 0 {
		// This should never happen.
		return "", fmt.Errorf("found 0 interfaces")
	}
	if len(interfaces) > 1 {
		// This should (ideally) never happen. If it does, advise the operator
		// to specify the IP address in the address field of the gRPC
		// configuration.
		return "", fmt.Errorf("found multiple interfaces, specify one of %q in the gRPC configuration", interfaces)
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
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "Reading JSON config file into config structure")

	if *grpcAddr != "" {
		c.NonceService.GRPC.Address = *grpcAddr
	}
	if *debugAddr != "" {
		c.NonceService.DebugAddr = *debugAddr
	}
	if *prefixOverride != "" && !c.NonceService.UseDerivablePrefix {
		c.NonceService.NoncePrefix = *prefixOverride
	}
	// TODO(#6610): Remove once we've moved to derivable prefixes by default.
	if c.NonceService.NoncePrefix != "" && c.NonceService.UseDerivablePrefix {
		cmd.Fail("Cannot set both 'noncePrefix' and 'useDerivablePrefix'")
	}

	// TODO(#6610): Remove once we've moved to derivable prefixes by default.
	if c.NonceService.UseDerivablePrefix && c.NonceService.PrefixSalt.PasswordFile == "" {
		cmd.Fail("Cannot set 'prefixSalt' without 'useDerivablePrefix'")
	}

	if c.NonceService.UseDerivablePrefix && c.NonceService.PrefixSalt.PasswordFile != "" {
		fmt.Println("Using derivable nonce prefix")
		salt, err := c.NonceService.PrefixSalt.Pass()
		cmd.FailOnError(err, "Failed to load 'prefixSalt' file.")
		c.NonceService.NoncePrefix, err = derivePrefix(salt, c.NonceService.GRPC.Address)
		cmd.FailOnError(err, "Failed to derive nonce prefix")
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
