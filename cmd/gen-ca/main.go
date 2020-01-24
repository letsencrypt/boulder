package main

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
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

// AllowedSigAlgs contains the allowed signature algorithms
var AllowedSigAlgs = map[string]x509.SignatureAlgorithm{
	"SHA256WithRSA":   x509.SHA256WithRSA,
	"SHA384WithRSA":   x509.SHA384WithRSA,
	"SHA512WithRSA":   x509.SHA512WithRSA,
	"ECDSAWithSHA256": x509.ECDSAWithSHA256,
	"ECDSAWithSHA384": x509.ECDSAWithSHA384,
	"ECDSAWithSHA512": x509.ECDSAWithSHA512,
}

// CertProfile contains the information required to generate a certificate
// for signing
type CertProfile struct {
	// SignatureAlgorithm should contain one of the allowed signature algorithms
	// in AllowedSigAlgs
	SignatureAlgorithm string

	// CommonName should contain the requested subject common name
	CommonName string
	// Organization should contain the requested subject organization
	Organization string
	// Country should contain the requested subject country code
	Country string

	// NotBefore should contain the requested NotBefore date for the
	// certificate in the format "2006-01-02 15:04:05". Dates will
	// always be UTC.
	NotBefore string
	// NotAfter should contain the requested NotAfter date for the
	// certificate in the format "2006-01-02 15:04:05". Dates will
	// always be UTC.
	NotAfter string

	// OCSPURL should contain the URL at which a OCSP responder that
	// can respond to OCSP requests for this certificate operates
	OCSPURL string
	// CRLURL should contain the URL at which CRLs for this certificate
	// can be found
	CRLURL string
	// IssuerURL should contain the URL at which the issuing certificate
	// can be found, this is only required if generating an intermediate
	// certificate
	IssuerURL string

	// PolicyOIDs should contain any OIDs to be inserted in a certificate
	// policies extension. These should be formatted in the standard OID
	// string format (i.e. "1.2.3")
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

func verifyProfile(profile CertProfile, root bool) error {
	if profile.NotBefore == "" {
		return errors.New("NotBefore in profile is required")
	}
	if profile.NotAfter == "" {
		return errors.New("NotAfter in profile is required")
	}
	if profile.SignatureAlgorithm == "" {
		return errors.New("SignatureAlgorithm in profile is required")
	}
	if profile.CommonName == "" {
		return errors.New("CommonName in profile is required")
	}
	if profile.Organization == "" {
		return errors.New("Organization in profile is required")
	}
	if profile.Country == "" {
		return errors.New("Country in profile is required")
	}
	if !root && profile.OCSPURL == "" {
		return errors.New("OCSPURL in profile is required for intermediates")
	}
	if !root && profile.CRLURL == "" {
		return errors.New("CRLURL in profile is required for intermediates")
	}
	if !root && profile.IssuerURL == "" {
		return errors.New("IssuerURL in profile is required for intermediates")
	}
	return nil
}

// makeTemplate generates the certificate template for use in x509.CreateCertificate
func makeTemplate(ctx pkcs11helpers.PKCtx, profile *CertProfile, pubKey []byte, session pkcs11.SessionHandle) (*x509.Certificate, error) {
	dateLayout := "2006-01-02 15:04:05"
	notBefore, err := time.Parse(dateLayout, profile.NotBefore)
	if err != nil {
		return nil, err
	}
	notAfter, err := time.Parse(dateLayout, profile.NotAfter)
	if err != nil {
		return nil, err
	}

	var ocspServer []string
	if profile.OCSPURL != "" {
		ocspServer = []string{profile.OCSPURL}
	}
	var crlDistributionPoints []string
	if profile.CRLURL != "" {
		crlDistributionPoints = []string{profile.CRLURL}
	}
	var issuingCertificateURL []string
	if profile.IssuerURL != "" {
		issuingCertificateURL = []string{profile.IssuerURL}
	}

	var policyOIDs []asn1.ObjectIdentifier
	for _, oidStr := range profile.PolicyOIDs {
		oid, err := parseOID(oidStr)
		if err != nil {
			return nil, err
		}
		policyOIDs = append(policyOIDs, oid)
	}

	sigAlg, ok := AllowedSigAlgs[profile.SignatureAlgorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported signature algorithm %q", profile.SignatureAlgorithm)
	}

	subjectKeyID := sha256.Sum256(pubKey)

	serial, err := ctx.GenerateRandom(session, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	cert := &x509.Certificate{
		SignatureAlgorithm:    sigAlg,
		SerialNumber:          big.NewInt(0).SetBytes(serial),
		BasicConstraintsValid: true,
		IsCA:                  true,
		Subject: pkix.Name{
			CommonName:   profile.CommonName,
			Organization: []string{profile.Organization},
			Country:      []string{profile.Country},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		OCSPServer:            ocspServer,
		CRLDistributionPoints: crlDistributionPoints,
		IssuingCertificateURL: issuingCertificateURL,
		PolicyIdentifiers:     policyOIDs,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          subjectKeyID[:],
	}

	return cert, nil
}

type failReader struct{}

func (fr *failReader) Read([]byte) (int, error) {
	return 0, errors.New("Empty reader used by x509.CreateCertificate")
}

func main() {
	module := flag.String("module", "", "PKCS#11 module to use")
	slot := flag.Uint("slot", 0, "ID of PKCS#11 slot containing token with signing key.")
	pin := flag.String("pin", "", "PKCS#11 token PIN. If empty, will assume PED based login.")
	label := flag.String("label", "", "PKCS#11 key label")
	id := flag.String("id", "", "PKCS#11 hex key ID (simplified format, i.e. ffff")
	profilePath := flag.String("profile", "", "Path to file containing certificate profile in JSON format. See https://godoc.org/github.com/letsencrypt/boulder/cmd/gen-ca#CertProfile for details.")
	pubKeyPath := flag.String("publicKey", "", "Path to file containing the subject public key in PEM format")
	issuerPath := flag.String("issuer", "", "Path to issuer cert if generating an intermediate")
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

	privKey, err := pkcs11helpers.GetKey(ctx, session, *label, *id)
	if err != nil {
		log.Fatalf("Failed to retrieve private key handle: %s", err)
	}
	log.Println("Retrieved private key handle")

	profileBytes, err := ioutil.ReadFile(*profilePath)
	if err != nil {
		log.Fatalf("Failed to read certificate profile %q: %s", *profilePath, err)
	}
	var profile CertProfile
	err = json.Unmarshal(profileBytes, &profile)
	if err != nil {
		log.Fatalf("Failed to parse certificate profile: %s", err)
	}
	if err = verifyProfile(profile, *issuerPath == ""); err != nil {
		log.Fatalf("Invalid certificate profile: %s", err)
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

	certTemplate, err := makeTemplate(ctx, &profile, pubPEM.Bytes, session)
	if err != nil {
		log.Fatalf("Failed to construct certificate template from profile: %s", err)
	}
	log.Println("Generated certificate template from profile")
	var issuer *x509.Certificate
	if *issuerPath != "" {
		// If generating an intermediate, load the parent issuer and
		// set the Authority Key Identifier in the template.
		issuerPEMBytes, err := ioutil.ReadFile(*issuerPath)
		if err != nil {
			log.Fatalf("Failed to read issuer certificate %q: %s", *issuerPath, err)
		}
		issuerPEM, _ := pem.Decode(issuerPEMBytes)
		if issuerPEM == nil {
			log.Fatal("Failed to parse issuer certificate PEM")
		}
		issuer, err = x509.ParseCertificate(issuerPEM.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse issuer certificate: %s", err)
		}
		certTemplate.AuthorityKeyId = issuer.SubjectKeyId
	} else {
		issuer = certTemplate
	}

	// x509.CreateCertificate uses a io.Reader here for signing methods that require
	// a source of randomness. Since PKCS#11 based signing generates needed randomness
	// at the HSM we don't need to pass a real reader. Instead of passing a nil reader
	// we use one that always returns errors in case the internal usage of this reader
	// changes.
	certBytes, err := x509.CreateCertificate(&failReader{}, certTemplate, issuer, pub, privKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	log.Printf("Signed certificate: %x\n", certBytes)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		log.Fatalf("Failed to parse signed certificate: %s", err)
	}

	// If generating a root then the signing key is the public key
	// in the cert itself, so set the parent to itself
	var parent *x509.Certificate
	if *issuerPath == "" {
		parent = cert
	} else {
		parent = issuer
	}
	if err := cert.CheckSignatureFrom(parent); err != nil {
		log.Fatalf("Failed to verify certificate signature: %s", err)
	}
	log.Println("Verified certificate signature")

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	log.Printf("Certificate PEM:\n%s", pemBytes)
	if err := ioutil.WriteFile(*outputPath, pemBytes, os.ModePerm); err != nil {
		log.Fatalf("Failed to write certificate to %q: %s", *outputPath, err)
	}
	log.Printf("Certificate written to %q\n", *outputPath)
}
