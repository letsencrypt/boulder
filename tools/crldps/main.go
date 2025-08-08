// crldps generates the list of CRL Distribution Point URIs for a given issuing
// CA and number of shards. It fetches and validates all of those shards. If
// it doesn't encounter any errors, it pretty-prints the list of all CRLDPs for
// disclosure in CCADB.
package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/crl/idp"
)

func main() {
	log.SetOutput(os.Stderr)

	fs := flag.NewFlagSet("crldps", flag.ContinueOnError)
	caPath := fs.String("ca", "", "path to an issuing intermediate CA certificate (required)")
	numShards := fs.Int("shards", 128, "number of CRL shards issued by the CA")
	err := fs.Parse(os.Args[1:])
	if err != nil || len(fs.Args()) != 0 {
		log.Println("Incorrect command line flags; usage:")
		fs.PrintDefaults()
		os.Exit(1)
	}

	issuer, err := core.LoadCert(*caPath)
	if err != nil {
		log.Fatalf("Failed to load issuer certificate from %q: %s", os.Args[1], err)
	}

	crldpBase := fmt.Sprintf("http://%s.c.lencr.org", strings.ToLower(issuer.Subject.CommonName))

	var (
		anyErr bool
		crldps []string
	)
	for shard := range *numShards {
		// We 1-index our CRL shards.
		crldp := fmt.Sprintf("%s/%d.crl", crldpBase, shard+1)

		resp, err := http.Get(crldp)
		if err != nil {
			anyErr = true
			log.Printf("Error downloading crl %q: %s", crldp, err)
			continue
		}

		crlDer, err := io.ReadAll(resp.Body)
		if err != nil {
			anyErr = true
			log.Printf("Error reading crl %q: %s", crldp, err)
			continue
		}
		resp.Body.Close()

		crl, err := x509.ParseRevocationList(crlDer)
		if err != nil {
			anyErr = true
			log.Printf("Error parsing crl %q: %s", crldp, err)
			continue
		}

		err = crl.CheckSignatureFrom(issuer)
		if err != nil {
			anyErr = true
			log.Printf("Error validating signature on crl %q: %s", crldp, err)
			continue
		}

		idps, err := idp.GetIDPURIs(crl.Extensions)
		if err != nil {
			anyErr = true
			log.Printf("Error extracting IDPs from crl %q: %s", crldp, err)
			continue
		}

		if !slices.Contains(idps, crldp) {
			anyErr = true
			log.Printf("Failed to find matching IDP in crl %q", crldp)
			continue
		}

		crldps = append(crldps, crldp)
	}

	if anyErr {
		log.Fatalf("Encountered one or more errors above; exiting")
	}

	// Do a final check of the one-past-the-end shard, to ensure the operator
	// gave the correct number of shards.
	{
		crldp := fmt.Sprintf("%s/%d.crl", crldpBase, *numShards+1)
		resp, err := http.Get(crldp)
		if err == nil && resp.StatusCode != http.StatusNotFound {
			log.Fatalf("Was unexpectedly able to fetch higher-numbered shard %q; please verify that the -shards flag is correct", crldp)
		}
	}

	out, err := json.MarshalIndent(crldps, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal list of CRLDPs: %s", err)
	}

	fmt.Println(string(out))
}
