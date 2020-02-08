// ceremony is a key/certificate ceremony tool.
package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/letsencrypt/boulder/pkcs11helpers"
)

type ceremonyType int

const (
	rootCeremony ceremonyType = iota
	intermediateCeremony
	keyCeremony
)

type ceremonyConfig struct {
	PKCS11Module       string       `yaml:"pkcs11-module"`
	CeremonyType       string       `yaml:"ceremony-type"`
	KeySlot            uint         `yaml:"key-slot"`
	KeyLabel           string       `yaml:"key-label"`
	KeyID              string       `yaml:"key-id"`
	KeyType            string       `yaml:"key-type"`
	ECDSACurve         string       `yaml:"ecdsa-curve"`
	PublicKeyPath      string       `yaml:"public-key-path"`
	CertificatePath    string       `yaml:"certificate-path"`
	IssuerPath         string       `yaml:"issuer-path"`
	CertificateProfile *certProfile `yaml:"certificate-profile"`
}

func (cc ceremonyConfig) Validate() error {
	if cc.PKCS11Module == "" {
		return errors.New("pkcs11-module is required")
	}
	if cc.CeremonyType != "root" && cc.CeremonyType != "intermediate" && cc.CeremonyType != "key" {
		return errors.New("ceremony-type can only be 'root', 'intermediate', or 'key'")
	}
	switch cc.CeremonyType {
	case "root":
		if cc.KeyLabel == "" {
			return errors.New("key-label is required")
		}
		if cc.KeyID != "" {
			return errors.New("key-id is not used for root ceremonies")
		}
		if cc.KeyType == "" {
			return errors.New("key-type is required")
		}
		if cc.KeyType != "rsa" && cc.KeyType != "ecdsa" {
			return errors.New("key-type can only be 'rsa' or 'ecdsa'")
		}
		if cc.KeyType == "rsa" && cc.ECDSACurve != "" {
			return errors.New("if key-type = \"rsa\" then ecdsa-curve is not used")
		}
		if cc.KeyType == "ecdsa" && cc.ECDSACurve == "" {
			return errors.New("if key-type = \"ecdsa\" then ecdsa-curve is required")
		}
		if cc.PublicKeyPath == "" {
			return errors.New("public-key-path is required")
		}
		if cc.CertificatePath == "" {
			return errors.New("certificate-path is required")
		}
		if cc.IssuerPath != "" {
			return errors.New("issuer-path is not used for root ceremonies")
		}
		if cc.CertificateProfile == nil {
			return errors.New("certificate-profile is required")
		}
		if err := verifyProfile(cc.CertificateProfile, true); err != nil {
			return fmt.Errorf("invalid certificate-profile: %s", err)
		}
	case "intermediate":
		if cc.KeyLabel == "" {
			return errors.New("key-label is required")
		}
		if cc.KeyID == "" {
			return errors.New("key-id is required")
		}
		if cc.KeyType != "" {
			return errors.New("key-type is not used for intermediate ceremonies")
		}
		if cc.ECDSACurve != "" {
			return errors.New("ecdsa-curve is not used for intermediate ceremonies")
		}
		if cc.PublicKeyPath == "" {
			return errors.New("public-key-path is required")
		}
		if cc.CertificatePath == "" {
			return errors.New("certificate-path is required")
		}
		if cc.IssuerPath == "" {
			return errors.New("issuer-path is required")
		}
		if cc.CertificateProfile == nil {
			return errors.New("certificate-profile is required")
		}
		if err := verifyProfile(cc.CertificateProfile, true); err != nil {
			return fmt.Errorf("invalid certificate-profile: %s", err)
		}
	case "key":
		if cc.KeyLabel == "" {
			return errors.New("key-label is required")
		}
		if cc.KeyID != "" {
			return errors.New("key-id is not used for key ceremonies")
		}
		if cc.KeyType == "" {
			return errors.New("key-type is required")
		}
		if cc.KeyType != "rsa" && cc.KeyType != "ecdsa" {
			return errors.New("key-type can only be 'rsa' or 'ecdsa'")
		}
		if cc.KeyType == "rsa" && cc.ECDSACurve != "" {
			return errors.New("if key-type = \"rsa\" then ecdsa-curve is not used")
		}
		if cc.KeyType == "ecdsa" && cc.ECDSACurve == "" {
			return errors.New("if key-type = \"ecdsa\" then ecdsa-curve is required")
		}
		if cc.PublicKeyPath == "" {
			return errors.New("public-key-path is required")
		}
		if cc.IssuerPath != "" {
			return errors.New("issuer-path is not used for key ceremonies")
		}
		if cc.CertificatePath != "" {
			return errors.New("certificate-path is not used for key ceremonies")
		}
		if cc.CertificateProfile != nil {
			return errors.New("certificate-profile is not used for key ceremonies")
		}
	}

	return nil
}

func main() {
	configPath := flag.String("config", "", "Path to ceremony configuration file")
	flag.Parse()

	if *configPath == "" {
		log.Fatal("--config is required")
	}
	configBytes, err := ioutil.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Failed to read config file: %s", err)
	}
	var config ceremonyConfig
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		log.Fatalf("Failed to parse config: %s", err)
	}

	if err = config.Validate(); err != nil {
		log.Fatalf("Failed to validate config: %s", err)
	}

	ctx, session, err := pkcs11helpers.Initialize(config.PKCS11Module, config.KeySlot, "")
	if err != nil {
		log.Fatalf("Failed to setup session and PKCS#11 context for slot %d: %s", config.KeySlot, err)
	}
	log.Printf("Opened PKCS#11 session for slot %d\n", config.KeySlot)

	switch config.CeremonyType {
	case "root":
		keyInfo, err := generateKey(ctx, session, config)
		if err != nil {
			log.Fatal(err)
		}
		signer, err := getKey(ctx, session, config.KeyLabel, keyInfo.id)
		if err != nil {
			log.Fatalf("Failed to retrieve signer: %s", err)
		}
		template, err := makeTemplate(ctx, session, config.CertificateProfile, keyInfo.der)
		if err != nil {
			log.Fatalf("Failed to create certificate profile: %s", err)
		}
		// x509.CreateCertificate uses a io.Reader here for signing methods that require
		// a source of randomness. Since PKCS#11 based signing generates needed randomness
		// at the HSM we don't need to pass a real reader. Instead of passing a nil reader
		// we use one that always returns errors in case the internal usage of this reader
		// changes.
		certBytes, err := x509.CreateCertificate(&failReader{}, template, template, keyInfo.key, signer)
		if err != nil {
			log.Fatalf("Failed to create certificate: %s", err)
		}
		log.Printf("Signed certificate: %x\n", certBytes)
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			log.Fatalf("Failed to parse signed certificate: %s", err)
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			log.Fatalf("Failed to verify certificate signature: %s", err)
		}
		log.Println("Verified certificate signature")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
		log.Printf("Certificate PEM:\n%s", pemBytes)
		if err := ioutil.WriteFile(config.CertificatePath, pemBytes, 0644); err != nil {
			log.Fatalf("Failed to write certificate to %q: %s", config.CertificatePath, err)
		}
		log.Printf("Certificate written to %q\n", config.CertificatePath)
	case "intermediate":
		keyID, err := hex.DecodeString(config.KeyID)
		if err != nil {
			log.Fatalf("Failed to decode key-id: %s", err)
		}
		signer, err := getKey(ctx, session, config.KeyLabel, keyID)
		if err != nil {
			log.Fatalf("Failed to retrieve private key handle: %s", err)
		}
		log.Println("Retrieved private key handle")

		pubPEMBytes, err := ioutil.ReadFile(config.PublicKeyPath)
		if err != nil {
			log.Fatalf("Failed to read public key %q: %s", config.PublicKeyPath, err)
		}
		pubPEM, _ := pem.Decode(pubPEMBytes)
		if pubPEM == nil {
			log.Fatal("Failed to parse public key")
		}
		pub, err := x509.ParsePKIXPublicKey(pubPEM.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse public key: %s", err)
		}
		issuerPEMBytes, err := ioutil.ReadFile(config.IssuerPath)
		if err != nil {
			log.Fatalf("Failed to read issuer certificate %q: %s", config.IssuerPath, err)
		}
		issuerPEM, _ := pem.Decode(issuerPEMBytes)
		if issuerPEM == nil {
			log.Fatal("Failed to parse issuer certificate PEM")
		}
		issuer, err := x509.ParseCertificate(issuerPEM.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse issuer certificate: %s", err)
		}
		template, err := makeTemplate(ctx, session, config.CertificateProfile, pubPEM.Bytes)
		if err != nil {
			log.Fatalf("Failed to create certificate profile: %s", err)
		}
		template.AuthorityKeyId = issuer.SubjectKeyId
		// x509.CreateCertificate uses a io.Reader here for signing methods that require
		// a source of randomness. Since PKCS#11 based signing generates needed randomness
		// at the HSM we don't need to pass a real reader. Instead of passing a nil reader
		// we use one that always returns errors in case the internal usage of this reader
		// changes.
		certBytes, err := x509.CreateCertificate(&failReader{}, template, issuer, pub, signer)
		if err != nil {
			log.Fatalf("Failed to create certificate: %s", err)
		}
		log.Printf("Signed certificate: %x\n", certBytes)
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			log.Fatalf("Failed to parse signed certificate: %s", err)
		}
		if err := cert.CheckSignatureFrom(issuer); err != nil {
			log.Fatalf("Failed to verify certificate signature: %s", err)
		}
		log.Println("Verified certificate signature")
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
		log.Printf("Certificate PEM:\n%s", pemBytes)
		if err := ioutil.WriteFile(config.CertificatePath, pemBytes, 0644); err != nil {
			log.Fatalf("Failed to write certificate to %q: %s", config.CertificatePath, err)
		}
		log.Printf("Certificate written to %q\n", config.CertificatePath)
	case "key":
		if _, err = generateKey(ctx, session, config); err != nil {
			log.Fatal(err)
		}
	}
}
