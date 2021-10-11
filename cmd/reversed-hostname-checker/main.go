/// Read a list of reversed hostnames, separated by newlines. Print only those
/// that are rejected by the current policy.

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/sa"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	pa, err := policy.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := pa.SetHostnamePolicyFile("../../test/hostname-policy.yaml"); err != nil {
		log.Fatal(err)
	}
	for scanner.Scan() {
		n := sa.ReverseName(string(scanner.Bytes()))
		if err := pa.WillingToIssue(identifier.DNSIdentifier(n)); err != nil {
			fmt.Println(n, err)
		}
	}
}
