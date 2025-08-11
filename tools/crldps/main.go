// crldps generates the list of CRL Distribution Point URIs for a given issuing
// CA and number of shards. The CRLDPs look like "http://x.c.lencr.org/n.crl",
// where "x" is the lowercased Subject Common Name of the issuing CA (e.g. "r3")
// and "n" is the one-indexed number of the shard. It fetches and validates all
// of those shards. If it doesn't encounter any errors, it pretty-prints the
// list of all CRLDPs for disclosure in CCADB.
package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/crl/idp"
)

// Matches the ABNF definition of a <label> per RFC 1035's Preferred Name Syntax
// https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.1
var rfc1035label = regexp.MustCompile("^[a-zA-Z]([-a-zA-Z0-9]*[a-zA-Z0-9])?$")

func main() {
	fs := flag.NewFlagSet("crldps", flag.ContinueOnError)
	caPath := fs.String("ca", "", "path to an issuing intermediate CA certificate (required)")
	numShards := fs.Int("shards", 0, "number of CRL shards issued by the CA (required)")
	err := fs.Parse(os.Args[1:])
	if err != nil || len(fs.Args()) != 0 || len(*caPath) == 0 || *numShards == 0 {
		log.Println("Incorrect command line flags; usage:")
		fs.PrintDefaults()
		os.Exit(1)
	}

	issuer, err := core.LoadCert(*caPath)
	if err != nil {
		log.Fatalf("Failed to load issuer certificate from %q: %s", os.Args[1], err)
	}

	if len(issuer.Subject.CommonName) > 63 || !rfc1035label.MatchString(issuer.Subject.CommonName) {
		log.Fatalf("Cannot construct CRLDP because issuer CN %q is not a valid domain label", issuer.Subject.CommonName)
	}

	client := http.Client{Timeout: 10 * time.Second}

	var (
		anyErr bool
		crldps []string
	)
	for shard := range *numShards {
		// We 1-index our CRL shards.
		crldp := crldpString(issuer, shard+1)

		err := fetchAndCheck(crldp, client, issuer)
		if err != nil {
			anyErr = true
			log.Printf("Error processing crl %q: %x", crldp, err)
			continue
		}

		crldps = append(crldps, crldp)
	}

	if anyErr {
		log.Fatalf("Encountered one or more errors above; exiting")
	}

	// Do two final checks of the zeroth and one-past-the-end shards, to ensure
	// the operator gave the correct number of shards and that the shard
	// generation is configured correctly.
	{
		crldp := crldpString(issuer, 0)
		resp, err := client.Get(crldp)
		if err != nil {
			log.Fatalf("Error checking for existence of zero shard %q: %s", crldp, err)
		} else if resp.StatusCode != http.StatusNotFound {
			log.Fatalf("Was unexpectedly able to fetch zero shard %q; please verify that the generated shards are one-indexed", crldp)
		}
	}
	{
		crldp := crldpString(issuer, *numShards+1)
		resp, err := client.Get(crldp)
		if err != nil {
			log.Fatalf("Error checking for existence of higher-nunbered shard %q: %s", crldp, err)
		} else if resp.StatusCode != http.StatusNotFound {
			log.Fatalf("Was unexpectedly able to fetch higher-numbered shard %q; please verify that the -shards flag is correct", crldp)
		}
	}

	out, err := json.MarshalIndent(crldps, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal list of CRLDPs: %s", err)
	}

	fmt.Println(string(out))
}

func crldpString(issuer *x509.Certificate, shard int) string {
	return (&url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s.c.lencr.org", strings.ToLower(issuer.Subject.CommonName)),
		Path:   fmt.Sprintf("%d.crl", shard),
	}).String()
}

func fetchAndCheck(crldp string, client http.Client, issuer *x509.Certificate) error {
	resp, err := client.Get(crldp)
	if err != nil {
		return fmt.Errorf("error downloading crl: %s", err)
	} else if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code while downloading crl: %s", http.StatusText(resp.StatusCode))
	}
	defer resp.Body.Close()

	crlDer, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading crl: %s", err)
	}

	crl, err := x509.ParseRevocationList(crlDer)
	if err != nil {
		return fmt.Errorf("error parsing crl: %s", err)
	}

	err = crl.CheckSignatureFrom(issuer)
	if err != nil {
		return fmt.Errorf("error validating crl signature: %s", err)
	}

	idps, err := idp.GetIDPURIs(crl.Extensions)
	if err != nil {
		return fmt.Errorf("error extracting IDPs: %s", err)
	}

	if !slices.Contains(idps, crldp) {
		return fmt.Errorf("crl does not contain matching IDP")
	}

	return nil
}
