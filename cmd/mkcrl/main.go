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

	"github.com/cloudflare/cfssl/crypto/pkcs11key"
	"github.com/cloudflare/cfssl/log"
)

var certFile = flag.String("ca", "", "JSON file for subject and validity")
var listFile = flag.String("revoked", "", "JSON list of revoked cert serials")
var module = flag.String("pkcs11-module", "", "PKCS#11 module")
var pin = flag.String("pkcs11-pin", "", "PKCS#11 password")
var token = flag.String("pkcs11-token", "", "PKCS#11 token name")
var label = flag.String("pkcs11-label", "", "PKCS#11 key label")

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
	switch {
	case len(*certFile) == 0:
		missing = true
		log.Critical("Missing cert file parameter")
		fallthrough
	case len(*listFile) == 0:
		missing = true
		log.Critical("Missing revoked list parameter")
		fallthrough
	case len(*module) == 0:
		missing = true
		log.Critical("Missing module parameter")
		fallthrough
	case len(*pin) == 0:
		missing = true
		log.Critical("Missing pin parameter")
		fallthrough
	case len(*token) == 0:
		missing = true
		log.Critical("Missing token parameter")
		fallthrough
	case len(*label) == 0:
		missing = true
		log.Critical("Missing label parameter")
	}
	if missing {
		log.Critical("All flags must be provided, bitch.")
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
