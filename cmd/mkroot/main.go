package main

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"time"

	//	"github.com/cloudflare/cfssl/crypto/pkcs11key"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/cloudflare/cfssl/log"
)

var configFile = flag.String("config", "", "JSON file for subject and validity")
var module = flag.String("pkcs11-module", "", "PKCS#11 module")
var pin = flag.String("pkcs11-pin", "", "PKCS#11 password")
var token = flag.String("pkcs11-token", "", "PKCS#11 token name")
var label = flag.String("pkcs11-label", "", "PKCS#11 key label")

type Config struct {
	Name struct {
		C  string
		O  string
		OU string
		CN string
	}
	NotBefore time.Time
	NotAfter  time.Time
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

	jsonConfig, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Criticalf("Unable to read config: %v", err)
		return
	}

	var config Config
	err = json.Unmarshal(jsonConfig, &config)
	if err != nil {
		log.Criticalf("Unable to parse config: %v", err)
		return
	}

	if len(config.Name.C) == 0 || len(config.Name.O) == 0 ||
		len(config.Name.CN) == 0 {
		log.Criticalf("Config must provide country, organizationName, and commonName")
		return
	}

	if config.NotBefore.After(config.NotAfter) {
		log.Criticalf("Invalid validity: notAfter is before notBefore")
		return
	}

	// Set up PKCS#11 key
	priv, err := pkcs11key.New(*module, *token, *pin, *label)
	if err != nil {
		log.Criticalf("Unable to instantiate PKCS#11 private key: %v", err)
		return
	}
	pub := priv.Public()

	// Generate serial number
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		log.Criticalf("Error generating serial number: %v", err)
		return
	}

	// Generate subject key ID
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Criticalf("Error serializing public key: %v", err)
		return
	}
	h := sha1.New()
	h.Write(pubDER)
	keyID := h.Sum(nil)

	// Sign the certificate
	rootTemplate := &x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,

		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      []string{config.Name.C},
			Organization: []string{config.Name.O},
			CommonName:   config.Name.CN,
		},
		NotBefore: config.NotBefore,
		NotAfter:  config.NotAfter,

		BasicConstraintsValid: true,
		IsCA: true,

		SubjectKeyId: keyID,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, pub, priv)
	if err != nil {
		log.Criticalf("Error signing certificate: %v", err)
		return
	}

	fmt.Println(string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rootDER,
	})))
}
