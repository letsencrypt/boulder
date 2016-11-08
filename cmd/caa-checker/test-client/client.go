package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/net/context"

	"github.com/letsencrypt/boulder/cmd"
	pb "github.com/letsencrypt/boulder/cmd/caa-checker/proto"
	bgrpc "github.com/letsencrypt/boulder/grpc"
	"github.com/letsencrypt/boulder/metrics"
)

func main() {
	addr := flag.String("addr", "boulder:9090", "CCS address")
	name := flag.String("name", "", "Name to check")
	issuer := flag.String("issuerDomain", "", "Issuer domain to check against")
	flag.Parse()

	// Set up a connection to the server.
	conn, err := bgrpc.ClientSetup(&cmd.GRPCClientConfig{
		ServerAddresses:       []string{*addr},
		ServerIssuerPath:      "test/grpc-creds/minica.pem",
		ClientCertificatePath: "test/grpc-creds/boulder-client/cert.pem",
		ClientKeyPath:         "test/grpc-creds/boulder-client/key.pem",
	}, metrics.NewNoopScope())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to setup client connection: %s\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	c := pb.NewCAACheckerClient(conn)

	r, err := c.ValidForIssuance(context.Background(), &pb.Check{Name: name, IssuerDomain: issuer})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ValidForIssuance call failed: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "%s valid for issuance: %t (records present: %t)\n", *name, *r.Valid, *r.Present)
}
