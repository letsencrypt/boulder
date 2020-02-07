// ceremony is a key/certificate ceremony tool.
package main

import (
	"bytes"
	"crypto"
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
	"github.com/miekg/pkcs11"
)

type ceremonyType int

const (
	rootCeremony ceremonyType = iota
	intermediateCeremony
	keyCeremony
)

type ceremonyConfig struct {
	CeremonyType       string `yaml:"ceremony-type"`
	PKCS11Module       string
	KeySlot            uint
	KeyPin             string // make --test-only-pin flag instead of config?
	KeyLabel           string
	KeyID              string
	KeyType            string
	ECDSACurve         string
	PublicKeyPath      string
	CertificatePath    string
	IssuerPath         string
	CertificateProfile *certProfile
}

func (cc ceremonyConfig) Validate() error {
	if cc.PKCS11Module == "" {
		return errors.New("pkcs11-module is required")
	}
	switch cc.CeremonyType {
	case "root":
		if cc.KeyLabel == "" {
			return errors.New("key-label is required")
		}
		if cc.KeyType == "" {
			return errors.New("key-type is required")
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
		if cc.KeyType == "" {
			return errors.New("key-type is required")
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

type generateArgs struct {
	mechanism    []*pkcs11.Mechanism
	privateAttrs []*pkcs11.Attribute
	publicAttrs  []*pkcs11.Attribute
}

func getRandomBytes(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle) ([]byte, error) {
	r, err := ctx.GenerateRandom(session, 4)
	if err != nil {
		return nil, err
	}
	return r, nil
}

const (
	rsaModLen = 2048
	rsaExp    = 65537
)

type keyInfo struct {
	key interface{}
	der []byte
	id  []byte
}

func generateKey(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, config ceremonyConfig) (*keyInfo, error) {
	var pubKey interface{}
	var keyID []byte
	var err error
	switch config.KeyType {
	case "RSA":
		pubKey, keyID, err = rsaGenerate(ctx, session, config.KeyLabel, rsaModLen, rsaExp)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key pair: %s", err)
		}
	case "ECDSA":
		pubKey, keyID, err = ecGenerate(ctx, session, config.KeyLabel, config.ECDSACurve)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key pair: %s", err)
		}
	}

	der, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal public key: %s", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	log.Printf("Public key PEM:\n%s\n", pemBytes)
	if err := ioutil.WriteFile(config.PublicKeyPath, pemBytes, 0644); err != nil {
		return nil, fmt.Errorf("Failed to write public key to %q: %s", config.PublicKeyPath, err)
	}
	log.Printf("Public key written to %q\n", config.PublicKeyPath)
	return &keyInfo{key: pubKey, der: der, id: keyID}, nil
}

// findObject looks up a PKCS#11 object handle based on the provided template.
// In the case where zero or more than one objects are found to match the
// template an error is returned.
func findObject(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if err := ctx.FindObjectsInit(session, tmpl); err != nil {
		return 0, err
	}
	handles, more, err := ctx.FindObjects(session, 1)
	if err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, errors.New("no objects found matching provided template")
	}
	if more {
		return 0, errors.New("more than one object matches provided template")
	}
	if err := ctx.FindObjectsFinal(session); err != nil {
		return 0, err
	}
	return handles[0], nil
}

// getKey constructs a x509Signer for the private key object associated with the
// given label and ID
func getKey(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, label string, id []byte) (*x509Signer, error) {
	// Retrieve the private key handle that will later be used for the certificate
	// signing operation
	privateHandle, err := findObject(ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve private key handle: %s", err)
	}
	attrs, err := ctx.GetAttributeValue(session, privateHandle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil)},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key type: %s", err)
	}
	if len(attrs) == 0 {
		return nil, errors.New("failed to retrieve key attributes")
	}

	// Retrieve the public key handle with the same CKA_ID as the private key
	// and construct a {rsa,ecdsa}.PublicKey for use in x509.CreateCertificate
	pubHandle, err := findObject(ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, attrs[0].Value),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve public key handle: %s", err)
	}
	var pub crypto.PublicKey
	var keyType pkcs11helpers.KeyType
	switch {
	// 0x00000000, CKK_RSA
	case bytes.Compare(attrs[0].Value, []byte{0, 0, 0, 0, 0, 0, 0, 0}) == 0:
		keyType = pkcs11helpers.RSAKey
		pub, err = pkcs11helpers.GetRSAPublicKey(ctx, session, pubHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve public key: %s", err)
		}
	// 0x00000003, CKK_ECDSA
	case bytes.Compare(attrs[0].Value, []byte{3, 0, 0, 0, 0, 0, 0, 0}) == 0:
		keyType = pkcs11helpers.ECDSAKey
		pub, err = pkcs11helpers.GetECDSAPublicKey(ctx, session, pubHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve public key: %s", err)
		}
	default:
		return nil, errors.New("unsupported key type")
	}

	return &x509Signer{
		ctx:          ctx,
		session:      session,
		objectHandle: privateHandle,
		keyType:      keyType,
		pub:          pub,
	}, nil
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

	ctx, session, err := pkcs11helpers.Initialize(config.PKCS11Module, config.KeySlot, config.KeyPin)
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
