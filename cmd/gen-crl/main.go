package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"crypto/rand"
	"io/ioutil"
	"fmt"
	"log"
	"path"
	"time"
	"crypto"

	"github.com/letsencrypt/boulder/pkcs11helpers"
)

type crlDef struct {
	num   int
	start time.Time
	end   time.Time
}

func generateDefs(total, initialNum int, startStr string, period, overlap time.Duration) ([]crlDef, error) {
	var crlDefs []crlDef
	start := time.Now()
	if startStr != "" {
		var err error
		start, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse start-date %q: %s", startStr, err)
		}
	}
	end := start.Add(period)
	for i := 0; i < total; i++ {
		crlDefs = append(crlDefs, crlDef{
			num:   i + initialNum,
			start: start,
			end:   end,
		})
		start = end.Add(-overlap)
		end = start.Add(period)
		log.Printf("CRL %d %s - %s\n", crlDefs[i].num, crlDefs[i].start, crlDefs[i].end)
	}
	return crlDefs, nil
}

func generateCRL(issuer *x509.Certificate, privKey crypto.Signer, def crlDef, dir, prefix string) error {
	crl, err := issuer.CreateCRL(rand.Reader, privKey, nil, def.start, def.end)
	if err != nil {
		return fmt.Errorf("failed to create CRL %d: %s", def.num, err)
	}
	log.Printf("Signed CRL %d\n", def.num)
	path := path.Join(dir, fmt.Sprintf("%s-%d.pem", prefix, def.num))
	if err = ioutil.WriteFile(path, crl, 0644); err != nil {
		return fmt.Errorf("failed to write CRL %d to %q: %s", def.num, "", err)
	}
	log.Printf("Written CRL %d to %q\n", def.num, path)
	return nil
}

func main() {
	module := flag.String("module", "", "PKCS#11 module to use")
	slot := flag.Uint("slot", 0, "ID of PKCS#11 slot containing token with signing key.")
	pin := flag.String("pin", "", "PKCS#11 token PIN. If empty, will assume PED based login.")
	label := flag.String("label", "", "PKCS#11 key label")
	id := flag.String("id", "", "PKCS#11 hex key ID (simplified format, i.e. ffff")
	issuerPath := flag.String("issuer", "", "Path to the PEM encoded issuer certificate")
	initialCRLNumber := flag.Int("crl-number", 0, "First CRL number in series")
	startDate := flag.String("start-date", "", "Last update date for first CRL in series (in the format '2006-01-02T15:04:05Z07:00'")
	numCRLs := flag.Int("num-crls", 0, "Number of CRLs in series to generate")
	validityPeriod := flag.Duration("validity-period", 0, "Validity period for each CRL in series")
	validityOverlap := flag.Duration("validity-overlap", 0, "Overlap in validity periods for each CRL in series")
	crlPrefix := flag.String("crl-prefix", "", "Prefix for the CRL files")
	crlDir := flag.String("crl-path", "", "Path to write CRLs to")
	flag.Parse()

	if *module == "" {
		log.Fatal("--module is required")
	}
	if *label == "" {
		log.Fatal("--label is required")
	}
	if *id == "" {
		log.Fatal("--id is required")
	}

	ctx, session, err := pkcs11helpers.Initialize(*module, *slot, *pin)
	if err != nil {
		log.Fatalf("Failed to setup session and PKCS#11 context: %s", err)
	}
	log.Println("Opened PKCS#11 session")

	privKey, err := pkcs11helpers.GetKey(ctx, session, *label, *id)
	if err != nil {
		log.Fatalf("Failed to retrieve private key handle: %s", err)
	}
	log.Println("Retrieved private key handle")

	issuerBytes, err := ioutil.ReadFile(*issuerPath)
	if err != nil {
		log.Fatalf("Failed to read issuer certificate %q: %s", *issuerPath, err)
	}
	issuerPEM, _ := pem.Decode(issuerBytes)
	issuer, err := x509.ParseCertificate(issuerPEM.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse issuer certificate %q: %s", *issuerPath, err)
	}

	
	crlDefs, err := generateDefs(*numCRLs, *initialCRLNumber, *startDate, *validityPeriod, *validityOverlap)
	if err != nil {
		log.Fatalf("Failed to generate CRL definitions: %s", err)
	}

	// TODO: verify we got what we want?

	for _, def := range crlDefs {
		if err = generateCRL(issuer, privKey, def, *crlDir, *crlPrefix); err != nil {
			log.Fatalf("Failed to sign and write CRL: %s", err)
		}
	}

}
