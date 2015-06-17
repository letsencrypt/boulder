package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	//	"github.com/cloudflare/cfssl/crypto/pkcs11key"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/log"
)

var certFile = flag.String("ca", "", "JSON file for subject and validity")
var listFile = flag.String("revoked", "", "JSON file with a list of pkix.RevokedCertificate objects")
var module = flag.String("pkcs11-module", "", "PKCS#11 module")
var pin = flag.String("pkcs11-pin", "", "PKCS#11 password")
var token = flag.String("pkcs11-token", "", "PKCS#11 token name")
var label = flag.String("pkcs11-label", "", "PKCS#11 key label")

// Config defines the configuration loaded from listFile.
type Config struct {
	ThisUpdate   time.Time
	NextUpdate   time.Time
	RevokedCerts []pkix.RevokedCertificate
}

func main() {
	// Validate input
	// All flags are required
	flag.Parse()
	missing := false
	flag.VisitAll(func(f *flag.Flag) {
		if len(f.Value.String()) == 0 {
			missing = true
		}
	})
	if missing {
		log.Critical("All flags must be provided.")
		flag.Usage()
		return
	}

	// Read the issuer cert
	certPEM, err := ioutil.ReadFile(*certFile)
	if err != nil {
		log.Criticalf("Unable to read certificate: %v", err)
		return
	}

	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Criticalf("Unable to parse certificate: %v", err)
		return
	}

	// Read the list of revoked certs
	jsonConfig, err := ioutil.ReadFile(*listFile)
	if err != nil {
		log.Criticalf("Unable to read list of revoked certs: %v", err)
		return
	}

	var config Config
	err = json.Unmarshal(jsonConfig, &config)
	if err != nil {
		log.Criticalf("Unable to parse list of revoked certs: %v", err)
		return
	}

	// Set up PKCS#11 key
	priv, err := pkcs11key.New(*module, *token, *pin, *label)
	if err != nil {
		log.Criticalf("Unable to instantiate PKCS#11 private key: %v", err)
		return
	}

	// Sign the CRL
	crlDER, err := cert.CreateCRL(rand.Reader, priv, config.RevokedCerts, config.ThisUpdate, config.NextUpdate)
	if err != nil {
		log.Criticalf("Error signing certificate: %v", err)
		return
	}

	fmt.Println(string(pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})))
}
