package main

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/pkcs11"

	"github.com/letsencrypt/boulder/pkcs11helpers"
)

type keyAlg int

const (
	rsaType keyAlg = iota
	ecdsaType
)

type p11Key struct {
	ctx pkcs11helpers.PKCtx

	session      pkcs11.SessionHandle
	objectHandle pkcs11.ObjectHandle
	keyType      keyAlg
}

// Hash identifiers required for PKCS#11 RSA signing. Only support SHA-256, SHA-384,
// and SHA-512
var hashIdentifiers = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func (p *p11Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if len(digest) != opts.HashFunc().Size() {
		return nil, errors.New("digest length doesn't match hash length")
	}

	mech := make([]*pkcs11.Mechanism, 1)
	switch p.keyType {
	case rsaType:
		mech[0] = pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)
		prefix, ok := hashIdentifiers[opts.HashFunc()]
		if !ok {
			return nil, errors.New("unsupported hash function")
		}
		digest = append(prefix, digest...)
	case ecdsaType:
		mech[0] = pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)
	}

	err = p.ctx.SignInit(p.session, mech, p.objectHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize signing operation: %s", err)
	}
	signature, err = p.ctx.Sign(p.session, digest)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %s", err)
	}
	return
}

func getPrivateKey(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, label string, idStr string) (*p11Key, error) {
	id, err := hex.DecodeString(idStr)
	if err != nil {
		return nil, err
	}

	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	if err := ctx.FindObjectsInit(session, tmpl); err != nil {
		return nil, err
	}
	handles, more, err := ctx.FindObjects(session, 1)
	if err != nil {
		return nil, err
	}
	if len(handles) == 0 {
		return nil, errors.New("no private keys found matching label and ID")
	}
	if more {
		return nil, errors.New("more than one object matches label and ID")
	}
	if err := ctx.FindObjectsFinal(session); err != nil {
		return nil, err
	}

	object := handles[0]
	attrs, err := ctx.GetAttributeValue(session, object, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil)})
	if err != nil || len(attrs) != 0 {
		return nil, fmt.Errorf("failed to retrieve key type: %s", err)
	}
	var keyType keyAlg
	switch attrs[0].Type {
	case pkcs11.CKK_RSA:
		keyType = rsaType
	case pkcs11.CKK_EC:
		keyType = ecdsaType
	}

	return &p11Key{ctx: ctx, session: session, objectHandle: object, keyType: keyType}, nil
}

var algToString = map[string]x509.SignatureAlgorithm{
	"SHA256WithRSA":   x509.SHA256WithRSA,
	"SHA384WithRSA":   x509.SHA384WithRSA,
	"SHA512WithRSA":   x509.SHA512WithRSA,
	"ECDSAWithSHA256": x509.ECDSAWithSHA256,
	"ECDSAWithSHA384": x509.ECDSAWithSHA384,
	"ECDSAWithSHA512": x509.ECDSAWithSHA512,
}

type certProfile struct {
	SignatureAlgorithm string

	Subject struct {
		CommonName   string
		Organization string
		Country      string
	}

	NotAfter  string
	NotBefore string

	OCSPURL   string
	CRLURL    string
	IssuerURL string

	PolicyOIDs []string
}

func parseOID(oidStr string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	for _, a := range strings.Split(oidStr, ".") {
		i, err := strconv.Atoi(a)
		if err != nil {
			return nil, err
		}
		oid = append(oid, i)
	}
	return oid, nil
}

const dateLayout = "2006-01-02 15:04:05"

func constructCert(profile *certProfile) (*x509.Certificate, error) {
	notBefore, err := time.Parse(dateLayout, profile.NotBefore)
	if err != nil {
		return nil, err
	}
	notAfter, err := time.Parse(dateLayout, profile.NotAfter)
	if err != nil {
		return nil, err
	}

	var policyOIDs []asn1.ObjectIdentifier
	for _, oidStr := range profile.PolicyOIDs {
		oid, err := parseOID(oidStr)
		if err != nil {
			return nil, err
		}
		policyOIDs = append(policyOIDs, oid)
	}

	sigAlg, ok := algToString[profile.SignatureAlgorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported signature algorithm %q", profile.SignatureAlgorithm)
	}

	cert := &x509.Certificate{
		SignatureAlgorithm:    sigAlg,
		BasicConstraintsValid: true,
		IsCA: true,
		Subject: pkix.Name{
			CommonName:   profile.Subject.CommonName,
			Organization: []string{profile.Subject.Organization},
			Country:      []string{profile.Subject.Country},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		OCSPServer:            []string{profile.OCSPURL},
		CRLDistributionPoints: []string{profile.CRLURL},
		IssuingCertificateURL: []string{profile.IssuerURL},
		PolicyIdentifiers:     policyOIDs,
		KeyUsage:              x509.KeyUsageCertSign & x509.KeyUsageCRLSign,
	}

	return cert, nil
}

func main() {
	module := flag.String("module", "", "PKCS#11 module to use")
	slot := flag.Uint("slot", 0, "Slot signing key is in")
	pin := flag.String("pin", "", "PIN for slot if not using PED to login")
	label := flag.String("label", "", "Signing key label")
	id := flag.String("id", "", "Signing key ID hex")
	profilePath := flag.String("profile", "", "Path to certificate profile")
	pubKeyPath := flag.String("publicKey", "", "Path to public key for certificate") // this could also be in the profile
	issuerPath := flag.String("issuer", "", "Path to issuer cert if generating a intermediate")
	outputPath := flag.String("output", "", "Path to store generated PEM certificate")
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
	if *profilePath == "" {
		log.Fatal("--profile is required")
	}
	if *pubKeyPath == "" {
		log.Fatal("--publicKey is required")
	}
	if *outputPath == "" {
		log.Fatal("--output is required")
	}

	ctx, session, err := pkcs11helpers.Initialize(*module, *slot, *pin)
	if err != nil {
		log.Fatalf("Failed to setup session and PKCS#11 context: %s", err)
	}
	privKey, err := getPrivateKey(ctx, session, *label, *id)
	if err != nil {
		log.Fatalf("Failed to retrieve private key handle: %s", err)
	}

	profileBytes, err := ioutil.ReadFile(*profilePath)
	if err != nil {
		log.Fatalf("Failed to read certificate profile %q: %s", *profilePath, err)
	}
	var profile *certProfile
	err = json.Unmarshal(profileBytes, profile)
	if err != nil {
		log.Fatalf("Failed to parse certificate profile: %s", err)
	}

	pubBytes, err := ioutil.ReadFile(*pubKeyPath)
	if err != nil {
		log.Fatalf("Failed to read public key %q: %s", *pubKeyPath, err)
	}
	pub, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		log.Fatalf("Failed to parse public key: %s", err)
	}

	certTmpl, err := constructCert(profile)
	if err != nil {
		log.Fatalf("Failed to construct certificate from profile: %s", err)
	}

	// get parent cert
	var issuer *x509.Certificate
	if *issuerPath != "" {
		issuerBytes, err := ioutil.ReadFile(*issuerPath)
		if err != nil {
			log.Fatalf("Failed to read issuer certificate %q: %s", *issuerPath, err)
		}
		issuer, err = x509.ParseCertificate(issuerBytes)
		if err != nil {
			log.Fatalf("Failed to parse certificate: %s", err)
		}
	} else {
		issuer = certTmpl
	}

	// We don't pass a random io.Reader here as the PKCS#11 wrapper doesn't use it
	certBytes, err := x509.CreateCertificate(nil, certTmpl, issuer, pub, privKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatalf("Failed to parse signed certificate: %s", err)
	}

	// verify cert signature
	if *issuerPath == "" {
		issuer = cert
	}
	if err := cert.CheckSignatureFrom(issuer); err != nil {
		log.Fatalf("Failed to verify certificate signature: %s", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	log.Printf("Certificate PEM:\n%s\n", pemBytes)
	if err := ioutil.WriteFile(*outputPath, pemBytes, os.ModePerm); err != nil {
		log.Fatalf("Failed to write certificate to %q: %s", *outputPath, err)
	}
	log.Printf("Certificate written to %q\n", *outputPath)
}
