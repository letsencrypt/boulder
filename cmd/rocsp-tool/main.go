package notmain

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/issuance"
	"github.com/letsencrypt/boulder/rocsp"
	rocsp_config "github.com/letsencrypt/boulder/rocsp/config"
	"github.com/letsencrypt/boulder/test/ocsp/helper"
	"golang.org/x/crypto/ocsp"
)

type config struct {
	ROCSPTool struct {
		Redis rocsp_config.RedisConfig
		// Issuers is a map from filenames to short issuer IDs.
		// Each filename must contain an issuer certificate. The short issuer
		// IDs are arbitrarily assigned and must be consistent across OCSP
		// components. For production we'll use the number part of the CN, i.e.
		// E1 -> 1, R3 -> 3, etc.
		Issuers map[string]int
	}
}

func init() {
	cmd.RegisterCommand("rocsp-tool", main)
}

func main() {
	if err := main2(); err != nil {
		log.Fatal(err)
	}
}

type ShortIDIssuer struct {
	*issuance.Certificate
	subject pkix.RDNSequence
	shortID byte
}

func loadIssuers(input map[string]int) ([]ShortIDIssuer, error) {
	var issuers []ShortIDIssuer
	for issuerFile, shortID := range input {
		if shortID > 255 || shortID < 0 {
			return nil, fmt.Errorf("invalid shortID %d (must be byte)", shortID)
		}
		cert, err := issuance.LoadCertificate(issuerFile)
		if err != nil {
			return nil, fmt.Errorf("reading issuer: %w", err)
		}
		var subject pkix.RDNSequence
		_, err = asn1.Unmarshal(cert.Certificate.RawSubject, &subject)
		if err != nil {
			return nil, fmt.Errorf("parsing issuer.RawSubject: %w", err)
		}
		var shortID byte = byte(shortID)
		for _, issuer := range issuers {
			if issuer.shortID == shortID {
				return nil, fmt.Errorf("duplicate shortID in config file: %d (for %q and %q)", shortID, issuer.subject, subject)
			}
			if !issuer.IsCA {
				return nil, fmt.Errorf("certificate for %q is not a CA certificate", subject)
			}
		}
		issuers = append(issuers, ShortIDIssuer{cert, subject, shortID})
	}
	return issuers, nil
}

func findIssuer(resp *ocsp.Response, issuers []ShortIDIssuer) (*ShortIDIssuer, error) {
	var responder pkix.RDNSequence
	_, err := asn1.Unmarshal(resp.RawResponderName, &responder)
	if err != nil {
		return nil, fmt.Errorf("parsing resp.RawResponderName: %w", err)
	}
	var responders strings.Builder
	for _, issuer := range issuers {
		fmt.Fprintf(&responders, "%s\n", issuer.subject)
		if bytes.Equal(issuer.RawSubject, resp.RawResponderName) {
			return &issuer, nil
		}
	}
	return nil, fmt.Errorf("no issuer found matching OCSP response for %s. Available issuers:\n%s\n", responder, responders.String())
}

func main2() error {
	configFile := flag.String("config", "", "File path to the configuration file for this service")
	flag.Parse()
	if *configFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	var c config
	err := cmd.ReadConfigFile(*configFile, &c)
	if err != nil {
		return fmt.Errorf("reading JSON config file: %w", err)
	}

	issuers, err := loadIssuers(c.ROCSPTool.Issuers)
	if err != nil {
		return fmt.Errorf("loading issuers: %w", err)
	}
	if len(issuers) == 0 {
		return fmt.Errorf("'issuers' section of config JSON is required.")
	}
	clk := cmd.Clock()
	client, err := rocsp_config.MakeClient(&c.ROCSPTool.Redis, clk)
	if err != nil {
		return fmt.Errorf("making client: %w", err)
	}

	for _, respFile := range flag.Args() {
		err := storeResponse(respFile, issuers, client, clk)
		if err != nil {
			return err
		}
	}
	return nil
}

func storeResponse(respFile string, issuers []ShortIDIssuer, client *rocsp.WritingClient, clk clock.Clock) error {
	ctx := context.Background()
	respBytes, err := ioutil.ReadFile(respFile)
	if err != nil {
		return fmt.Errorf("reading response file %q: %w", respFile, err)
	}
	resp, err := ocsp.ParseResponse(respBytes, nil)
	if err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	issuer, err := findIssuer(resp, issuers)
	if err != nil {
		return fmt.Errorf("finding issuer for response: %w", err)
	}

	// Re-parse the response, this time verifying with the appropriate issuer
	resp, err = ocsp.ParseResponse(respBytes, issuer.Certificate.Certificate)
	if err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	serial := core.SerialToString(resp.SerialNumber)

	if resp.NextUpdate.Before(clk.Now()) {
		return fmt.Errorf("response for %s expired %s ago", serial,
			clk.Now().Sub(resp.NextUpdate))
	}

	// Note: Here we set the TTL to slightly more than the lifetime of the
	// OCSP response. In ocsp-updater we'll want to set it to the lifetime
	// of the certificate, so that the metadata field doesn't fall out of
	// storage even if we are down for days. However, in this tool we don't
	// have the full certificate, so this will do.
	ttl := resp.NextUpdate.Sub(clk.Now()) + time.Hour

	log.Printf("storing response for %s, generated %s, ttl %g hours",
		serial,
		resp.ThisUpdate,
		ttl.Hours(),
	)

	err = client.StoreResponse(ctx, respBytes, issuer.shortID, ttl)
	if err != nil {
		return fmt.Errorf("storing response: %w", err)
	}

	retrievedResponse, err := client.GetResponse(ctx, serial)
	if err != nil {
		return fmt.Errorf("getting response: %w", err)
	}

	parsedRetrievedResponse, err := ocsp.ParseResponse(retrievedResponse, issuer.Certificate.Certificate)
	if err != nil {
		return fmt.Errorf("parsing retrieved response: %w", err)
	}
	log.Printf("retrieved %s", helper.PrettyResponse(parsedRetrievedResponse))
	return nil
}
