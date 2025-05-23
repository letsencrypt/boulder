// Read a list of reversed hostnames and/or IP addresses, separated by newlines.
// Print only those that are rejected by the current policy.
//
// IP addresses must be represented in their reverse DNS hostname forms, which
// are then reversed. For example:
//
// 192.168.1.1 -> 1.1.168.192.in-addr.arpa -> arpa.in-addr.192.168.1.1
//
// 3fff:aaa:a:c0ff:ee:a:bad:deed ->
// d.e.e.d.d.a.b.0.a.0.0.0.e.e.0.0.f.f.0.c.a.0.0.0.a.a.a.0.f.f.f.3.ip6.arpa ->
// arpa.ip6.3.f.f.f.0.a.a.a.0.0.0.a.c.0.f.f.0.0.e.e.0.0.0.a.0.b.a.d.d.e.e.d

package notmain

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"

	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/policy"
	"github.com/letsencrypt/boulder/sa"
)

func init() {
	cmd.RegisterCommand("reversed-hostname-checker", main, nil)
}

func main() {
	inputFilename := flag.String("input", "", "File containing a list of reversed hostnames to check, newline separated. Defaults to stdin")
	policyFile := flag.String("policy", "test/hostname-policy.yaml", "File containing a hostname policy in yaml.")
	flag.Parse()

	var input io.Reader
	var err error
	if *inputFilename == "" {
		input = os.Stdin
	} else {
		input, err = os.Open(*inputFilename)
		if err != nil {
			log.Fatalf("opening %s: %s", *inputFilename, err)
		}
	}

	scanner := bufio.NewScanner(input)
	logger := cmd.NewLogger(cmd.SyslogConfig{StdoutLevel: 7})
	logger.Info(cmd.VersionString())
	pa, err := policy.New(nil, nil, logger)
	if err != nil {
		log.Fatal(err)
	}
	err = pa.LoadHostnamePolicyFile(*policyFile)
	if err != nil {
		log.Fatalf("reading %s: %s", *policyFile, err)
	}
	var errors bool
	for scanner.Scan() {
		n, err := sa.DecodeIssuedName(scanner.Text())
		if err != nil {
			errors = true
			fmt.Printf("%s: %s\n", n, err)
		}
		var ident identifier.ACMEIdentifier
		ip, err := netip.ParseAddr(n)
		if err != nil {
			ident = identifier.NewIP(ip)
		} else {
			ident = identifier.NewDNS(n)
		}
		err = pa.WillingToIssue(identifier.ACMEIdentifiers{ident})
		if err != nil {
			errors = true
			fmt.Printf("%s: %s\n", n, err)
		}
	}
	if errors {
		os.Exit(1)
	}
}
