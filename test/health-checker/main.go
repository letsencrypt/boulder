package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/letsencrypt/boulder/cmd"
	bcreds "github.com/letsencrypt/boulder/grpc/creds"
)

func main() {
	serverAddr := flag.String("addr", "", "Address of the gRPC server to check")
	configFile := flag.String("config", "", "Path to the TLS configuration file")
	timeout := flag.String("timeout", "100s", "How long (as a duration string) to try before giving up (default: 10s)")
	flag.Parse()
	if *serverAddr == "" || *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var tlsConfig cmd.TLSConfig
	err := cmd.ReadConfigFile(*configFile, &tlsConfig)
	cmd.FailOnError(err, "failed to read json config")

	tc, err := tlsConfig.Load()
	cmd.FailOnError(err, "failed to load TLS credentials")

	host, _, err := net.SplitHostPort(*serverAddr)
	cmd.FailOnError(err, "failed to parse server address")
	creds := bcreds.NewClientCredentials(tc.RootCAs, tc.Certificates, host)

	duration, err := time.ParseDuration(*timeout)
	cmd.FailOnError(err, "failed to parse timeout string")
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)

	for {
		select {
		case <-ticker.C:
			fmt.Printf("Connecting to %s health service\n", *serverAddr)
			conn, err := grpc.Dial("dns:///"+*serverAddr, grpc.WithTransportCredentials(creds))
			cmd.FailOnError(err, "failed to connect to service")

			client := healthpb.NewHealthClient(conn)
			ctx2, cancel2 := context.WithTimeout(ctx, duration/10)
			defer cancel2()
			req := &healthpb.HealthCheckRequest{
				Service: "",
			}

			resp, err := client.Check(ctx2, req)

			if err != nil {
				fmt.Fprintf(os.Stderr, "got error connecting to health service %s: %s\n", *serverAddr, err)
			} else {
				if resp.Status != healthpb.HealthCheckResponse_SERVING {
					cmd.Fail(fmt.Sprintf("service %s failed health check with status %s", *serverAddr, resp.Status))
				}
				return
			}

		case <-ctx.Done():
			cmd.Fail(fmt.Sprintf("timed out waiting for %s health check", *serverAddr))
		}
	}
}
