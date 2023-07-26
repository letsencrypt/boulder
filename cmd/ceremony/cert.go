package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/linter"
	"github.com/letsencrypt/boulder/pkcs11helpers"
)

var kp goodkey.KeyPolicy

func init() {
	var err error
	kp, err = goodkey.NewKeyPolicy(&goodkey.Config{FermatRounds: 100}, nil)
	if err != nil {
		log.Fatal("Could not create goodkey.KeyPolicy")
	}
}

type policyInfoConfig struct {
	OID string
	// Deprecated: we do not include the id-qt-cps policy qualifier in our
	// certificate policy extensions anymore.
	CPSURI string `yaml:"cps-uri"`
}

// certProfile contains the information required to generate a certificate
type certProfile struct {
	// SignatureAlgorithm should contain one of the allowed signature algorithms
	// in AllowedSigAlgs
	SignatureAlgorithm string `yaml:"signature-algorithm"`

	// CommonName should contain the requested subject common name
	CommonName string `yaml:"common-name"`
	// Organization should contain the requested subject organization
	Organization string `yaml:"organization"`
	// Country should contain the requested subject country code
	Country string `yaml:"country"`

	// NotBefore should contain the requested NotBefore date for the
	// certificate in the format "2006-01-02 15:04:05". Dates will
	// always be UTC.
	NotBefore string `yaml:"not-before"`
	// NotAfter should contain the requested NotAfter date for the
	// certificate in the format "2006-01-02 15:04:05". Dates will
	// always be UTC.
	NotAfter string `yaml:"not-after"`

	// OCSPURL should contain the URL at which a OCSP responder that
	// can respond to OCSP requests for this certificate operates
	OCSPURL string `yaml:"ocsp-url"`
	// CRLURL should contain the URL at which CRLs for this certificate
	// can be found
	CRLURL string `yaml:"crl-url"`
	// IssuerURL should contain the URL at which the issuing certificate
	// can be found, this is only required if generating an intermediate
	// certificate
	IssuerURL string `yaml:"issuer-url"`

	// Policies should contain any OIDs to be inserted in a certificate
	// policies extension. It should be empty for Root certs, and contain the
	// BRs "domain-validated" Reserved Policy Identifier for Intermediates.
	Policies []policyInfoConfig `yaml:"policies"`

	// KeyUsages should contain the set of key usage bits to set
	KeyUsages []string `yaml:"key-usages"`
}

// AllowedSigAlgs contains the allowed signature algorithms
var AllowedSigAlgs = map[string]x509.SignatureAlgorithm{
	"SHA256WithRSA":   x509.SHA256WithRSA,
	"SHA384WithRSA":   x509.SHA384WithRSA,
	"SHA512WithRSA":   x509.SHA512WithRSA,
	"ECDSAWithSHA256": x509.ECDSAWithSHA256,
	"ECDSAWithSHA384": x509.ECDSAWithSHA384,
	"ECDSAWithSHA512": x509.ECDSAWithSHA512,
}

type certType int

const (
	rootCert certType = iota
	intermediateCert
	ocspCert
	crlCert
	crossCert
	requestCert
)

// Subject returns a pkix.Name from the appropriate certProfile fields
func (profile *certProfile) Subject() pkix.Name {
	return pkix.Name{
		CommonName:   profile.CommonName,
		Organization: []string{profile.Organization},
		Country:      []string{profile.Country},
	}
}

func (profile *certProfile) verifyProfile(ct certType) error {
	if ct == requestCert {
		if profile.NotBefore != "" {
			return errors.New("not-before cannot be set for a CSR")
		}
		if profile.NotAfter != "" {
			return errors.New("not-after cannot be set for a CSR")
		}
		if profile.SignatureAlgorithm != "" {
			return errors.New("signature-algorithm cannot be set for a CSR")
		}
		if profile.OCSPURL != "" {
			return errors.New("ocsp-url cannot be set for a CSR")
		}
		if profile.CRLURL != "" {
			return errors.New("crl-url cannot be set for a CSR")
		}
		if profile.IssuerURL != "" {
			return errors.New("issuer-url cannot be set for a CSR")
		}
		if profile.Policies != nil {
			return errors.New("policies cannot be set for a CSR")
		}
		if profile.KeyUsages != nil {
			return errors.New("key-usages cannot be set for a CSR")
		}
	} else {
		if profile.NotBefore == "" {
			return errors.New("not-before is required")
		}
		if profile.NotAfter == "" {
			return errors.New("not-after is required")
		}
		if profile.SignatureAlgorithm == "" {
			return errors.New("signature-algorithm is required")
		}
	}
	if profile.CommonName == "" {
		return errors.New("common-name is required")
	}
	if profile.Organization == "" {
		return errors.New("organization is required")
	}
	if profile.Country == "" {
		return errors.New("country is required")
	}

	if ct == rootCert {
		if len(profile.Policies) != 0 {
			return errors.New("policies should not be set on root certs")
		}
	}

	if ct == intermediateCert {
		if profile.CRLURL == "" {
			return errors.New("crl-url is required for intermediates")
		}
		if profile.IssuerURL == "" {
			return errors.New("issuer-url is required for intermediates")
		}
		if len(profile.Policies) != 1 || profile.Policies[0].OID != "2.23.140.1.2.1" {
			return errors.New("policy should be exactly BRs domain-validated for intermediates")
		}
	}

	if ct == crossCert {
		if profile.CRLURL == "" {
			return errors.New("crl-url is required for cross-signed subordinates CAs")
		}
		if profile.IssuerURL == "" {
			return errors.New("issuer-url is required for cross-signed subordiante CAs")
		}
	}

	if ct == ocspCert || ct == crlCert {
		if len(profile.KeyUsages) != 0 {
			return errors.New("key-usages cannot be set for a delegated signer")
		}
		if profile.CRLURL != "" {
			return errors.New("crl-url cannot be set for a delegated signer")
		}
		if profile.OCSPURL != "" {
			return errors.New("ocsp-url cannot be set for a delegated signer")
		}
	}
	return nil
}

func parseOID(oidStr string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	for _, a := range strings.Split(oidStr, ".") {
		i, err := strconv.Atoi(a)
		if err != nil {
			return nil, err
		}
		if i <= 0 {
			return nil, errors.New("OID components must be >= 1")
		}
		oid = append(oid, i)
	}
	return oid, nil
}

var stringToKeyUsage = map[string]x509.KeyUsage{
	"Digital Signature": x509.KeyUsageDigitalSignature,
	"CRL Sign":          x509.KeyUsageCRLSign,
	"Cert Sign":         x509.KeyUsageCertSign,
}

var oidOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

func generateSKID(pk []byte) ([]byte, error) {
	var pkixPublicKey struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}
	if _, err := asn1.Unmarshal(pk, &pkixPublicKey); err != nil {
		return nil, err
	}
	skid := sha256.Sum256(pkixPublicKey.BitString.Bytes)
	return skid[:], nil
}

// makeTemplate generates the certificate template for use in x509.CreateCertificate
func makeTemplate(randReader io.Reader, profile *certProfile, pubKey []byte, ct certType) (*x509.Certificate, error) {
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

	subjectKeyID, err := generateSKID(pubKey)
	if err != nil {
		return nil, err
	}

	serial := make([]byte, 16)
	_, err = randReader.Read(serial)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	var ku x509.KeyUsage
	for _, kuStr := range profile.KeyUsages {
		kuBit, ok := stringToKeyUsage[kuStr]
		if !ok {
			return nil, fmt.Errorf("unknown key usage %q", kuStr)
		}
		ku |= kuBit
	}
	if ct == ocspCert {
		ku = x509.KeyUsageDigitalSignature
	} else if ct == crlCert {
		ku = x509.KeyUsageCRLSign
	}
	if ku == 0 {
		return nil, errors.New("at least one key usage must be set")
	}

	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(0).SetBytes(serial),
		BasicConstraintsValid: true,
		IsCA:                  true,
		Subject:               profile.Subject(),
		OCSPServer:            ocspServer,
		CRLDistributionPoints: crlDistributionPoints,
		IssuingCertificateURL: issuingCertificateURL,
		KeyUsage:              ku,
		SubjectKeyId:          subjectKeyID,
	}

	if ct != requestCert {
		sigAlg, ok := AllowedSigAlgs[profile.SignatureAlgorithm]
		if !ok {
			return nil, fmt.Errorf("unsupported signature algorithm %q", profile.SignatureAlgorithm)
		}
		cert.SignatureAlgorithm = sigAlg
		notBefore, err := time.Parse(time.DateTime, profile.NotBefore)
		if err != nil {
			return nil, err
		}
		cert.NotBefore = notBefore
		notAfter, err := time.Parse(time.DateTime, profile.NotAfter)
		if err != nil {
			return nil, err
		}
		cert.NotAfter = notAfter
	}

	switch ct {
	// rootCert and crossCert do not get EKU or MaxPathZero
	case ocspCert:
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
		// ASN.1 NULL is 0x05, 0x00
		ocspNoCheckExt := pkix.Extension{Id: oidOCSPNoCheck, Value: []byte{5, 0}}
		cert.ExtraExtensions = append(cert.ExtraExtensions, ocspNoCheckExt)
		cert.IsCA = false
	case crlCert:
		cert.IsCA = false
	case requestCert, intermediateCert:
		// id-kp-serverAuth and id-kp-clientAuth are included in intermediate
		// certificates in order to technically constrain them. id-kp-serverAuth
		// is required by 7.1.2.2.g of the CABF Baseline Requirements, but
		// id-kp-clientAuth isn't. We include id-kp-clientAuth as we also include
		// it in our end-entity certificates.
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		cert.MaxPathLenZero = true
	}

	for _, policyConfig := range profile.Policies {
		oid, err := parseOID(policyConfig.OID)
		if err != nil {
			return nil, err
		}
		cert.PolicyIdentifiers = append(cert.PolicyIdentifiers, oid)
	}

	return cert, nil
}

// failReader exists to be passed to x509.CreateCertificate which requires
// a source of randomness for signing methods that require a source of
// randomness. Since HSM based signing will generate its own randomness
// we don't need a real reader. Instead of passing a nil reader we use one
// that always returns errors in case the internal usage of this reader
// changes.
type failReader struct{}

func (fr *failReader) Read([]byte) (int, error) {
	return 0, errors.New("empty reader used by x509.CreateCertificate")
}

func generateCSR(profile *certProfile, signer crypto.Signer) ([]byte, error) {
	csrDER, err := x509.CreateCertificateRequest(&failReader{}, &x509.CertificateRequest{
		Subject: profile.Subject(),
	}, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create and sign CSR: %s", err)
	}
	return csrDER, nil
}

// issueLintCert issues a linting certificate from a given template certificate
// signed by a given issuer and returns the certificate or an error. The public
// key from the loaded certificate is checked by the GoodKey package.
func issueLintCert(tbs, issuer *x509.Certificate, subjectPubKey crypto.PublicKey, signer crypto.Signer, skipLints []string) (*x509.Certificate, error) {
	lintCertBytes, err := linter.Check(tbs, subjectPubKey, issuer, signer, skipLints)
	if err != nil {
		return nil, fmt.Errorf("certificate failed pre-issuance lint: %w", err)
	}

	lintCert, err := x509.ParseCertificate(lintCertBytes)
	if err != nil {
		return nil, err
	}

	err = kp.GoodKey(context.Background(), lintCert.PublicKey)
	if err != nil {
		return nil, err
	}

	return lintCert, nil
}

// pubLoadAndDecode loads a PEM encoded certificate specified by filename and
// returns the raw bytes, an interface containing an encoded public key, and an
// error. The public key from the loaded certificate is checked by the GoodKey
// package.
func pubLoadAndDecode(PublicKeyPath string) ([]byte, any, error) {
	pubPEMBytes, err := os.ReadFile(PublicKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key %q: %s", PublicKeyPath, err)
	}

	pubPEM, _ := pem.Decode(pubPEMBytes)
	if pubPEM == nil {
		return nil, nil, fmt.Errorf("failed to decode public key bytes")
	}

	pub, err := x509.ParsePKIXPublicKey(pubPEM.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %s", err)
	}

	err = kp.GoodKey(context.Background(), pub)
	if err != nil {
		return nil, nil, err
	}

	return pubPEM.Bytes, pub, nil
}

func equalPubKeys(a, b interface{}) bool {
	aBytes, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bBytes, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytes.Equal(aBytes, bBytes)
}

func openSigner(cfg PKCS11SigningConfig, pubKey crypto.PublicKey) (crypto.Signer, *hsmRandReader, error) {
	session, err := pkcs11helpers.Initialize(cfg.Module, cfg.SigningSlot, cfg.PIN)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup session and PKCS#11 context for slot %d: %s",
			cfg.SigningSlot, err)
	}
	log.Printf("Opened PKCS#11 session for slot %d\n", cfg.SigningSlot)
	signer, err := session.NewSigner(cfg.SigningLabel, pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve private key handle: %s", err)
	}
	if !equalPubKeys(signer.Public(), pubKey) {
		return nil, nil, fmt.Errorf("signer pubkey did not match issuer pubkey")
	}
	log.Println("Retrieved private key handle")
	return signer, newRandReader(session), nil
}

// loadCert loads a PEM certificate specified by filename or returns an error.
// The public key from the loaded certificate is checked by the GoodKey package.
func loadCert(filename string) (cert *x509.Certificate, err error) {
	certPEM, err := os.ReadFile(filename)
	if err != nil {
		return
	}
	log.Printf("Loaded certificate from %s\n", filename)
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("No data in cert PEM file %s", filename)
	}
	cert, err = x509.ParseCertificate(block.Bytes)

	goodkeyErr := kp.GoodKey(context.Background(), cert.PublicKey)
	if goodkeyErr != nil {
		return nil, goodkeyErr
	}

	return
}

func signAndWriteCert(tbs, issuer *x509.Certificate, subjectPubKey crypto.PublicKey, signer crypto.Signer, certPath string) (*x509.Certificate, error) {
	// x509.CreateCertificate uses a io.Reader here for signing methods that require
	// a source of randomness. Since PKCS#11 based signing generates needed randomness
	// at the HSM we don't need to pass a real reader. Instead of passing a nil reader
	// we use one that always returns errors in case the internal usage of this reader
	// changes.
	certBytes, err := x509.CreateCertificate(&failReader{}, tbs, issuer, subjectPubKey, signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %s", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	log.Printf("Signed certificate PEM:\n%s", pemBytes)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed certificate: %s", err)
	}
	if tbs == issuer {
		// If cert is self-signed we need to populate the issuer subject key to
		// verify the signature
		issuer.PublicKey = cert.PublicKey
		issuer.PublicKeyAlgorithm = cert.PublicKeyAlgorithm
	}

	err = cert.CheckSignatureFrom(issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to verify certificate signature: %s", err)
	}
	err = writeFile(certPath, pemBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to write certificate to %q: %s", certPath, err)
	}
	log.Printf("Certificate written to %q\n", certPath)

	return cert, nil
}

// checkOutputFile returns an error if the filename is empty,
// or if a file already exists with that filename.
func checkOutputFile(filename, fieldname string) error {
	if filename == "" {
		return fmt.Errorf("outputs.%s is required", fieldname)
	}
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		return fmt.Errorf("outputs.%s is %q, which already exists",
			fieldname, filename)
	}
	return nil
}
