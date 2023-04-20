package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/letsencrypt/boulder/cmd"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/metrics"
)

type config struct {
	GRPC *cmd.GRPCClientConfig
	TLS  *cmd.TLSConfig
}

func main() {
	// Flag and config parsing and validation.
	configFile := flag.String("config", "", "Path to the TLS configuration file")
	serverAddr := flag.String("addr", "", "Address of the gRPC server to check")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	cmd.FailOnError(err, "failed to read json config")

	if c.GRPC.ServerAddress == "" && *serverAddr == "" {
		cmd.Fail("must specify either -addr flag or client.ServerAddress config")
	} else if c.GRPC.ServerAddress != "" && *serverAddr != "" {
		cmd.Fail("cannot specify both -addr flag and client.ServerAddress config")
	} else if c.GRPC.ServerAddress == "" {
		c.GRPC.ServerAddress = *serverAddr
	}

	scope, _ := cmd.StatsAndLogging(cmd.SyslogConfig{}, "")
	fmt.Println("DEBUG: 1")

	tlsConfig, err := c.TLS.Load(scope)
	fmt.Println("DEBUG: 2")
	cmd.FailOnError(err, "failed to load TLS credentials")

	// GRPC connection prerequisites.
	clk := cmd.Clock()
	fmt.Println("DEBUG: 3")

	// Health check retry and timeout.
	ticker := time.NewTicker(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*c.GRPC.Timeout.Duration)
	fmt.Println("DEBUG: 4")
	defer cancel()

	for {
		select {
		case <-ticker.C:
			fmt.Fprintf(os.Stderr, "Connecting to %s health service\n", *serverAddr)
			fmt.Println("DEBUG: 4.5")
			_, hostOverride, err := c.GRPC.MakeTargetAndHostOverride()
			fmt.Println("DEBUG: 5")
			cmd.FailOnError(err, "")

			// Set the hostOverride to match the dNSName in the server certificate.
			c.GRPC.HostOverride = strings.Replace(hostOverride, ".service.consul", ".boulder", 1)

			// Set up the GRPC connection.
			conn, err := bgrpc.ClientSetup(c.GRPC, tlsConfig, metrics.NoopRegisterer, clk)
			fmt.Println("DEBUG: 6")
			cmd.FailOnError(err, "failed to connect to service")
			client := healthpb.NewHealthClient(conn)
			ctx2, cancel2 := context.WithTimeout(ctx, c.GRPC.Timeout.Duration)
			defer cancel2()

			// Make the health check.
			req := &healthpb.HealthCheckRequest{
				Service: "",
			}
			fmt.Println("DEBUG: 77")
			resp, err := client.Check(ctx2, req)
			fmt.Println(err)
			if err != nil {
				fmt.Fprintf(os.Stderr, "got error connecting to health service %s: %s\n", *serverAddr, err)
			} else if resp.Status == healthpb.HealthCheckResponse_SERVING {
				return
			} else {
				cmd.Fail(fmt.Sprintf("service %s failed health check with status %s", *serverAddr, resp.Status))
			}

		case <-ctx.Done():
			fmt.Println("DEBUG: here?")
			cmd.Fail(fmt.Sprintf("timed out waiting for %s health check", *serverAddr))
		}
	}
}
