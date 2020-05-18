package main

import (
	"bytes"
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

	"github.com/letsencrypt/boulder/pkcs11helpers"
	"github.com/miekg/pkcs11"
)

type cpsPolicy struct {
	OID    string
	Values []string
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

	// PolicyOIDs should contain any OIDs to be inserted in a certificate
	// policies extension. These should be formatted in the standard OID
	// string format (i.e. "1.2.3"). This should only be used for policies
	// which don't need any policyQualifiers.
	PolicyOIDs []string `yaml:"policy-oids"`

	// CPSPolicies should contain any PolicyInformation extensions with
	// id-qt-cps type policyQualifiers to be inserted into the certificate.
	// The OIDs should be formatted in the standard OID string format
	// (i.e. "1.2.3")
	CPSPolicies []cpsPolicy `yaml:"cps-policies`

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

func (profile *certProfile) verifyProfile(root bool) error {
	if profile.NotBefore == "" {
		return errors.New("not-before is required")
	}
	if profile.NotAfter == "" {
		return errors.New("not-after is required")
	}
	if profile.SignatureAlgorithm == "" {
		return errors.New("signature-algorithm is required")
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
	if !root && profile.OCSPURL == "" {
		return errors.New("ocsp-url is required for intermediates")
	}
	if !root && profile.CRLURL == "" {
		return errors.New("crl-url is required for intermediates")
	}
	if !root && profile.IssuerURL == "" {
		return errors.New("issuer-url is required for intermediates")
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
		oid = append(oid, i)
	}
	return oid, nil
}

var stringToKeyUsage = map[string]x509.KeyUsage{
	"Digital Signature": x509.KeyUsageDigitalSignature,
	"CRL Sign":          x509.KeyUsageCRLSign,
	"Cert Sign":         x509.KeyUsageCertSign,
}

type policyQualifier struct {
	Id    asn1.ObjectIdentifier
	Value string `asn1:"tag:optional,ia5"`
}

type policyInformation struct {
	Policy     asn1.ObjectIdentifier
	Qualifiers []policyQualifier `asn1:"tag:optional,omitempty"`
}

var (
	oidExtensionCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidCPSQualifier                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}
)

// makeTemplate generates the certificate template for use in x509.CreateCertificate
func makeTemplate(randReader io.Reader, profile *certProfile, pubKey []byte) (*x509.Certificate, error) {
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

	sigAlg, ok := AllowedSigAlgs[profile.SignatureAlgorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported signature algorithm %q", profile.SignatureAlgorithm)
	}

	subjectKeyID := sha256.Sum256(pubKey)

	serial := make([]byte, 16)
	_, err = randReader.Read(serial)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	var ku x509.KeyUsage
	if len(profile.KeyUsages) == 0 {
		return nil, errors.New("key usages must be set")
	}
	for _, kuStr := range profile.KeyUsages {
		kuBit, ok := stringToKeyUsage[kuStr]
		if !ok {
			return nil, fmt.Errorf("unknown key usage %q", kuStr)
		}
		ku |= kuBit
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
		KeyUsage:              ku,
		SubjectKeyId:          subjectKeyID[:],
	}

	if len(profile.PolicyOIDs) > 0 || len(profile.CPSPolicies) > 0 {
		policyExt := pkix.Extension{Id: oidExtensionCertificatePolicies}
		var policies []policyInformation
		for _, oidStr := range profile.PolicyOIDs {
			oid, err := parseOID(oidStr)
			if err != nil {
				return nil, err
			}
			policies = append(policies, policyInformation{Policy: oid})
		}
		for _, p := range profile.CPSPolicies {
			oid, err := parseOID(p.OID)
			if err != nil {
				return nil, err
			}
			if len(p.Values) == 0 {
				return nil, errors.New("cps-policies.values cannot be empty")
			}
			qualifiers := make([]policyQualifier, len(p.Values))
			for i, q := range p.Values {
				qualifiers[i] = policyQualifier{Id: oidCPSQualifier, Value: q}
			}
			policies = append(policies, policyInformation{Policy: oid, Qualifiers: qualifiers})
		}
		policyExt.Value, err = asn1.Marshal(policies)
		if err != nil {
			return nil, err
		}
		cert.ExtraExtensions = append(cert.ExtraExtensions, policyExt)
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
	return 0, errors.New("Empty reader used by x509.CreateCertificate")
}

// x509Signer is a convenience wrapper used for converting between the
// PKCS#11 ECDSA signature format and the RFC 5480 one which is required
// for X.509 certificates
type x509Signer struct {
	ctx pkcs11helpers.PKCtx

	session      pkcs11.SessionHandle
	objectHandle pkcs11.ObjectHandle
	keyType      pkcs11helpers.KeyType

	pub crypto.PublicKey
}

// Sign wraps pkcs11helpers.Sign. If the signing key is ECDSA then the signature
// is converted from the PKCS#11 format to the RFC 5480 format. For RSA keys a
// conversion step is not needed.
func (p *x509Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signature, err := pkcs11helpers.Sign(p.ctx, p.session, p.objectHandle, p.keyType, digest, opts.HashFunc())
	if err != nil {
		return nil, err
	}

	if p.keyType == pkcs11helpers.ECDSAKey {
		// Convert from the PKCS#11 format to the RFC 5480 format so that
		// it can be used in a X.509 certificate
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

// newSigner constructs a x509Signer for the private key object associated with the
// given label and ID. Unlike letsencrypt/pkcs11key this method doesn't rely on
// having the actual public key object in order to retrieve the private key
// handle. This is because we already have the key pair object ID, and as such
// do not need to query the HSM to retrieve it.
func newSigner(ctx pkcs11helpers.PKCtx, session pkcs11.SessionHandle, label string, id []byte) (crypto.Signer, error) {
	// Retrieve the private key handle that will later be used for the certificate
	// signing operation
	privateHandle, err := pkcs11helpers.FindObject(ctx, session, []*pkcs11.Attribute{
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
	pubHandle, err := pkcs11helpers.FindObject(ctx, session, []*pkcs11.Attribute{
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
	case bytes.Equal(attrs[0].Value, []byte{0, 0, 0, 0, 0, 0, 0, 0}):
		keyType = pkcs11helpers.RSAKey
		pub, err = pkcs11helpers.GetRSAPublicKey(ctx, session, pubHandle)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve public key: %s", err)
		}
	// 0x00000003, CKK_ECDSA
	case bytes.Equal(attrs[0].Value, []byte{3, 0, 0, 0, 0, 0, 0, 0}):
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
