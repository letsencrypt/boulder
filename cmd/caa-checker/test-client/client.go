package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	pb "github.com/rolandshoemaker/caa-thing/proto"
)

func main() {
	addr := flag.String("addr", "localhost:2020", "CCS address")
	name := flag.String("name", "", "Name to check")
	flag.Parse()

	// Set up a connection to the server.
	conn, err := grpc.Dial(*addr, grpc.WithInsecure())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to dial '%s': %s\n", *addr, err)
		os.Exit(1)
	}
	defer conn.Close()
	c := pb.NewCAACheckerClient(conn)

	r, err := c.ValidForIssuance(context.Background(), &pb.Domain{*name})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ValidForIssuance call failed: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "%s valid for issuance: %v\n", *name, r.Valid)
}
