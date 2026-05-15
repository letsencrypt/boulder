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
	"slices"
	"strconv"
	"strings"
	"time"
)

type policyInfoConfig struct {
	OID string
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

	// EKUs must be either "none" (used for self-signed roots), "server" (used
	// for modern single-purpose hierarchies), or "both" (used for legacy
	// hierarchies with both id-kp-tlsClientAuth and id-kp-tlsServerAuth). If
	// empty, defaults to "none" for root ceremonies and to "server" for others.
	//
	// TODO: Remove this when we no longer issue any tlsClientAuth CA certs.
	EKUs string `yaml:"ekus"`
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

	if ct == intermediateCert || ct == crossCert {
		if profile.CRLURL == "" {
			return errors.New("crl-url is required for subordinate CAs")
		}
		if profile.IssuerURL == "" {
			return errors.New("issuer-url is required for subordinate CAs")
		}

		// BR 7.1.2.10.5 CA Certificate Certificate Policies
		// OID 2.23.140.1.2.1 is CABF BRs Domain Validated
		if len(profile.Policies) != 1 || profile.Policies[0].OID != "2.23.140.1.2.1" {
			return errors.New("policy should be exactly BRs domain-validated for subordinate CAs")
		}
	}

	return nil
}

func parseOID(oidStr string) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	for a := range strings.SplitSeq(oidStr, ".") {
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

func generateSKID(pk []byte) ([]byte, error) {
	var pkixPublicKey struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}
	if _, err := asn1.Unmarshal(pk, &pkixPublicKey); err != nil {
		return nil, err
	}

	// RFC 7093 Section 2 Additional Methods for Generating Key Identifiers: The
	// keyIdentifier [may be] composed of the leftmost 160-bits of the SHA-256
	// hash of the value of the BIT STRING subjectPublicKey (excluding the tag,
	// length, and number of unused bits).
	skid := sha256.Sum256(pkixPublicKey.BitString.Bytes)
	return skid[0:20:20], nil
}

// makeTemplate generates the certificate template for use in x509.CreateCertificate
func makeTemplate(randReader io.Reader, profile *certProfile, pubKey []byte, tbcs *x509.Certificate, ct certType) (*x509.Certificate, error) {
	// Handle "unrestricted" vs "restricted" subordinate CA profile specifics.
	if ct == crossCert && tbcs == nil {
		return nil, fmt.Errorf("toBeCrossSigned cert field was nil, but was required to gather EKUs for the lint cert")
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
	if ku == 0 {
		return nil, errors.New("at least one key usage must be set")
	}

	var ekus []x509.ExtKeyUsage
	if ct == rootCert {
		// rootCert does not get EKU or MaxPathZero.
		// 		BR 7.1.2.1.2 Root CA Extensions
		// 		Extension 	Presence 	Critical 	Description
		// 		extKeyUsage 	MUST NOT 	N 	-
		if profile.EKUs != "" && profile.EKUs != "none" {
			return nil, fmt.Errorf("root certificates MUST NOT have an EKU extension; profile configured %q", profile.EKUs)
		}
	} else {
		switch profile.EKUs {
		case "", "server":
			// By default, only include id-kp-tlsServerAuth. This reflects the move
			// towards single-purpose hierarchies, as required by the Chrome Root
			// Program, among others.
			ekus = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		case "both":
			// Until June 15, 2026, including both EKUs is acceptable.
			// https://googlechrome.github.io/chromerootprogram/#132-promote-use-of-dedicated-tls-server-authentication-pki-hierarchies
			// 1.3.2 Promote use of Dedicated TLS Server Authentication PKI Hierarchies
			// ...
			// All corresponding unexpired and unrevoked subordinate CA certificates operated beneath an existing root included in the Chrome Root Store MUST:
			// if disclosed to the CCADB before June 15, 2026: include the extendedKeyUsage extension and (a) only assert an extendedKeyUsage purpose of id-kp-serverAuth or (b) only assert extendedKeyUsage purposes of id-kp-serverAuth and id-kp-clientAuth.
			// ...
			//
			// Note: this safety check uses on notBefore rather than a disclosure date, so it's imperfect but still useful.
			notBefore, err := time.Parse(time.DateTime, profile.NotBefore)
			if err != nil {
				return nil, fmt.Errorf("parsing notBefore: %s", err)
			}
			if notBefore.Before(time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)) {
				ekus = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
			} else {
				return nil, fmt.Errorf("notBefore of %s is too late for including clientAuth EKU", tbcs.NotAfter.Format(time.RFC3339))
			}
		default:
			return nil, fmt.Errorf("unrecognized EKUs %q; must be 'none', 'server', or 'both'", profile.EKUs)
		}
	}
	if ct == crossCert && len(tbcs.ExtKeyUsage) != 0 && !slices.Equal(ekus, tbcs.ExtKeyUsage) {
		return nil, fmt.Errorf("existing cert has EKUs %v, but cross-certificate profile has EKUs %v", tbcs.ExtKeyUsage, ekus)
	}

	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(0).SetBytes(serial),
		BasicConstraintsValid: true,
		IsCA:                  true,
		Subject:               profile.Subject(),
		CRLDistributionPoints: crlDistributionPoints,
		IssuingCertificateURL: issuingCertificateURL,
		KeyUsage:              ku,
		ExtKeyUsage:           ekus,
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
			return nil, fmt.Errorf("parsing notBefore: %s", err)
		}
		notAfter, err := time.Parse(time.DateTime, profile.NotAfter)
		if err != nil {
			return nil, fmt.Errorf("parsing notAfter: %s", err)
		}
		validity := notAfter.Add(time.Second).Sub(notBefore)
		if ct == rootCert && validity >= 9132*24*time.Hour {
			// The value 9132 comes directly from the BRs, where it is described
			// as "approximately 25 years". It's equal to 365 * 25 + 7, to allow
			// for some leap years.
			return nil, fmt.Errorf("root cert validity too large: %s >= 25 years", validity)
		} else if (ct == intermediateCert || ct == crossCert) && validity >= 8*365*24*time.Hour {
			// Our CP/CPS states "at most 8 years", so we calculate that number
			// in the most conservative way (i.e. not accounting for leap years)
			// to give ourselves a buffer.
			return nil, fmt.Errorf("subordinate CA cert validity too large: %s >= 8 years", validity)
		}
		cert.NotBefore = notBefore
		cert.NotAfter = notAfter
	}

	switch ct {
	case requestCert, intermediateCert:
		// Issuing intermediates must always have MaxPathLen 0.
		cert.MaxPathLenZero = true
	case crossCert:
		// Cross-signs should have the same MaxPathLen as the existing cert.
		cert.MaxPathLenZero = tbcs.MaxPathLenZero
		// The SKID needs to match the previous SKID, no matter how it was computed.
		cert.SubjectKeyId = tbcs.SubjectKeyId
	}

	for _, policyConfig := range profile.Policies {
		x509OID, err := x509.ParseOID(policyConfig.OID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s as OID: %w", policyConfig.OID, err)
		}
		cert.Policies = append(cert.Policies, x509OID)
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
