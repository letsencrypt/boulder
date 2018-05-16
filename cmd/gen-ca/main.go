package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
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
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/pkcs11"

	"github.com/letsencrypt/boulder/pkcs11helpers"
)

type x509Signer struct {
	ctx pkcs11helpers.PKCtx

	session      pkcs11.SessionHandle
	objectHandle pkcs11.ObjectHandle
	keyType      pkcs11helpers.KeyType

	pub crypto.PublicKey
}

func (p *x509Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := pkcs11helpers.Sign(p.ctx, p.session, p.objectHandle, p.keyType, digest, opts.HashFunc())
	if err != nil {
		return nil, err
	}

	if p.keyType == pkcs11helpers.ECDSAKey {
		// Convert from the PKCS#11 format to the RFC 5480 format so that
		// it can be used in a x509 certificate
		r := big.NewInt(0).SetBytes(signature[:len(signature)/2])
		s := big.NewInt(0).SetBytes(signature[len(signature)/2:])
		signature, err = asn1.Marshal(struct {
			R, S *big.Int
		}{R: r, S: s})
		if err != nil {
			return nil, fmt.Errorf("failed to convert signature to RFC 5480 format: %s", err)
		}
	}
	return signature, nil
}

func (p *x509Signer) Public() crypto.PublicKey {
	return p.pub
}

func findObject(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, tmpl []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if err := ctx.FindObjectsInit(session, tmpl); err != nil {
		return 0, err
	}
	handles, more, err := ctx.FindObjects(session, 1)
	if err != nil {
		return 0, err
	}
	if len(handles) == 0 {
		return 0, errors.New("no objects found matching label and ID")
	}
	if more {
		return 0, errors.New("more than one object matches label and ID")
	}
	if err := ctx.FindObjectsFinal(session); err != nil {
		return 0, err
	}
	return handles[0], nil
}

func getKey(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, label string, idStr string) (*x509Signer, error) {
	id, err := hex.DecodeString(idStr)
	if err != nil {
		return nil, err
	}

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
	// CKK_RSA, 0x00000000
	case bytes.Compare(attrs[0].Value, []byte{0, 0, 0, 0, 0, 0, 0, 0}) == 0:
		keyType = pkcs11helpers.RSAKey
		pub, err = pkcs11helpers.GetRSAPublicKey(ctx, session, pubHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve public key: %s", err)
		}
	// CKK_ECDSA, 0x00000003
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

	NotBefore string
	NotAfter  string

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
	if oid == nil {
		return nil, fmt.Errorf("%q is not a valid OID", oidStr)
	}
	return oid, nil
}

const dateLayout = "2006-01-02 15:04:05"

func constructCert(ctx pkcs11helpers.PKCtx, profile *certProfile, pubKey []byte, session pkcs11.SessionHandle) (*x509.Certificate, error) {
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
	// generate serial number
	serial, err := ctx.GenerateRandom(session, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}
	keyHash := sha256.Sum256(pubKey)

	cert := &x509.Certificate{
		SignatureAlgorithm:    sigAlg,
		SerialNumber:          big.NewInt(0).SetBytes(serial),
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
		SubjectKeyId:          keyHash[:],
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
	log.Println("Opened PKCS#11 session")

	privKey, err := getKey(ctx, session, *label, *id)
	if err != nil {
		log.Fatalf("Failed to retrieve private key handle: %s", err)
	}
	log.Println("Retrieved private key handle")

	profileBytes, err := ioutil.ReadFile(*profilePath)
	if err != nil {
		log.Fatalf("Failed to read certificate profile %q: %s", *profilePath, err)
	}
	var profile certProfile
	err = json.Unmarshal(profileBytes, &profile)
	if err != nil {
		log.Fatalf("Failed to parse certificate profile: %s", err)
	}

	pubPEMBytes, err := ioutil.ReadFile(*pubKeyPath)
	if err != nil {
		log.Fatalf("Failed to read public key %q: %s", *pubKeyPath, err)
	}
	pubPEM, _ := pem.Decode(pubPEMBytes)
	if pubPEM == nil {
		log.Fatal("Failed to parse public key")
	}
	pub, err := x509.ParsePKIXPublicKey(pubPEM.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse public key: %s", err)
	}

	certTmpl, err := constructCert(ctx, &profile, pubPEM.Bytes, session)
	if err != nil {
		log.Fatalf("Failed to construct certificate from profile: %s", err)
	}
	log.Println("Generated tbs certificate")
	var issuer *x509.Certificate
	if *issuerPath != "" {
		// If generating an intermediate load the parent issuer and
		// set the Authority Key Identifier in the template
		issuerBytes, err := ioutil.ReadFile(*issuerPath)
		if err != nil {
			log.Fatalf("Failed to read issuer certificate %q: %s", *issuerPath, err)
		}
		issuer, err = x509.ParseCertificate(issuerBytes)
		if err != nil {
			log.Fatalf("Failed to parse certificate: %s", err)
		}
		certTmpl.AuthorityKeyId = issuer.SubjectKeyId
	} else {
		issuer = certTmpl
	}

	// We don't pass a random io.Reader here as the PKCS#11 wrapper doesn't use it
	certBytes, err := x509.CreateCertificate(nil, certTmpl, issuer, pub, privKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	log.Println("Signed certificate")
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatalf("Failed to parse signed certificate: %s", err)
	}

	// If generating a root then the signing key is the public key
	// in the cert itself, so set the parent to itself
	if *issuerPath == "" {
		issuer = cert
	}
	if err := cert.CheckSignatureFrom(issuer); err != nil {
		log.Fatalf("Failed to verify certificate signature: %s", err)
	}
	log.Println("Verifed certificate signature")

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	log.Printf("Certificate PEM:\n%s", pemBytes)
	if err := ioutil.WriteFile(*outputPath, pemBytes, os.ModePerm); err != nil {
		log.Fatalf("Failed to write certificate to %q: %s", *outputPath, err)
	}
	log.Printf("Certificate written to %q\n", *outputPath)
}
