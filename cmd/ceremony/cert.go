package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"
)

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
