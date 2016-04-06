package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/google.golang.org/grpc"

	"github.com/letsencrypt/boulder/cmd"
	pb "github.com/letsencrypt/boulder/cmd/caa-checker/proto"
	bgrpc "github.com/letsencrypt/boulder/grpc"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:2020", "CCS address")
	name := flag.String("name", "", "Name to check")
	issuer := flag.String("issuerDomain", "", "Issuer domain to check against")
	flag.Parse()

	// Set up a connection to the server.
	creds, err := bgrpc.LoadClientCreds(&cmd.GRPCClientConfig{
		ServerHostname:        "localhost",
		ServerIssuerPath:      "test/grpc-creds/ca.der",
		ClientCertificatePath: "test/grpc-creds/client.pem",
		ClientKeyPath:         "test/grpc-creds/key.pem",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load creds: %s\n", err)
		os.Exit(1)
	}
	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to dial '%s': %s\n", *addr, err)
		os.Exit(1)
	}
	defer conn.Close()
	c := pb.NewCAACheckerClient(conn)

	r, err := c.ValidForIssuance(context.Background(), &pb.Check{Name: *name, IssuerDomain: *issuer})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ValidForIssuance call failed: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "%s valid for issuance: %t\n", *name, r.Valid)
}
