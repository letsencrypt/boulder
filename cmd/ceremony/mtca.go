package main

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/letsencrypt/boulder/core/reloid"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/linter"
	"github.com/letsencrypt/boulder/strictyaml"
	"github.com/letsencrypt/boulder/unsigned"
)

type mtcaConfig struct {
	CeremonyType string `yaml:"ceremony-type"`
	Inputs       struct {
		PublicKeyPath string `yaml:"public-key-path"`
	} `yaml:"inputs"`
	Outputs struct {
		CertificatePath string `yaml:"certificate-path"`
	} `yaml:"outputs"`
	CertProfile struct {
		// PolicyURL is *not* included in the certificate. It is a mandatory pointer
		// to the profile documented in our CPS with which this profile complies.
		// It must point to a specific subsection of a specific version of the
		// markdown source of our CPS.
		PolicyURL string `yaml:"policy-url"`

		// MTCAID should contain the Relative OID which identifies this MTCA.
		MTCAID string `yaml:"mtcaid"`

		// NotBefore should contain the requested NotBefore date for the certificate
		// in the format `2006-01-02 15:04:05`. Dates must be UTC.
		NotBefore string `yaml:"not-before"`
		// NotAfter should contain the requested NotAfter date for the certificate
		// in the format `2006-01-02 15:04:05`. Dates must be UTC.
		NotAfter string `yaml:"not-after"`

		// TlogPrefix should be the base URL under which this MTCA's tlog API
		// endpoints can be found. It must be an https:// URL.
		TlogPrefix string `yaml:"tlog-prefix"`
	} `yaml:"certificate-profile"`
	SkipLints []string `yaml:"skip-lints"`
}

func mtcaCeremony(configBytes []byte) error {
	var config mtcaConfig
	err := strictyaml.Unmarshal(configBytes, &config)
	if err != nil {
		return fmt.Errorf("failed to parse config: %s", err)
	}
	log.Printf("Preparing MTCA ceremony for %s\n", config.Outputs.CertificatePath)

	err = config.validate()
	if err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	template, err := config.template()
	if err != nil {
		return fmt.Errorf("creating template: %w", err)
	}

	keyPEM, err := os.ReadFile(config.Inputs.PublicKeyPath)
	if err != nil {
		return fmt.Errorf("reading pubkey file: %w", err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("no data in cert PEM file %q", config.Inputs.PublicKeyPath)
	}

	pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parsing pubkey: %w", err)
	}

	kp, err := goodkey.NewPolicy(&goodkey.Config{AllowedKeys: &goodkey.AllowedKeys{MLDSA44: true}}, nil)
	if err != nil {
		return fmt.Errorf("creating key policy: %w", err)
	}

	err = kp.GoodKey(context.Background(), pubkey)
	if err != nil {
		return fmt.Errorf("pubkey does not meet policy: %w", err)
	}

	throwawaySigner, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		return fmt.Errorf("creating throwaway signer: %w", err)
	}

	lintCert, err := linter.Check(template, pubkey, template, throwawaySigner, linter.Config{}, config.SkipLints)
	if err != nil {
		return fmt.Errorf("linting certificate: %w", err)
	}

	cert, err := unsigned.Design(lintCert, true)
	if err != nil {
		return fmt.Errorf("removing signature: %w", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	err = writeFile(config.Outputs.CertificatePath, pemBytes)
	if err != nil {
		return fmt.Errorf("writing certificate to %q: %s", config.Outputs.CertificatePath, err)
	}

	log.Printf("Certificate written to %q\n", config.Outputs.CertificatePath)
	return nil
}

func (mc mtcaConfig) validate() error {
	// Input fields
	if mc.Inputs.PublicKeyPath == "" {
		return errors.New("inputs.public-key-path is required")
	}

	// Output fields
	err := checkOutputFile(mc.Outputs.CertificatePath, "certificate-path")
	if err != nil {
		return err
	}

	// Certificate profile
	if mc.CertProfile.PolicyURL == "" {
		return errors.New("policy-url is required")
	}
	if !policyURLRegex.MatchString(mc.CertProfile.PolicyURL) {
		return fmt.Errorf("policy-url must point to a specific subsection of a specific version of our CPS: %s", policyURLRegex.String())
	}
	if mc.CertProfile.MTCAID == "" {
		return errors.New("mtcaid is required")
	}
	if mc.CertProfile.NotBefore == "" {
		return errors.New("not-before is required")
	}
	if mc.CertProfile.NotAfter == "" {
		return errors.New("not-after is required")
	}
	if mc.CertProfile.TlogPrefix == "" {
		return errors.New("tlog-prefix is required")
	}
	if strings.HasSuffix(mc.CertProfile.TlogPrefix, "/") {
		return errors.New("tlog-prefix must not end with a slash")
	}

	return nil
}

func (mc mtcaConfig) template() (*x509.Certificate, error) {
	// We want 128 bits of randomness, plus a prefix to ensure that the serial is
	// never shorter than that, even if the CSPRNG generates lots of leading zeroes.
	const randBits = 128
	serialBytes := make([]byte, (randBits/8)+1)
	serialBytes[0] = 0x01
	rand.Read(serialBytes[1:])
	serial := big.NewInt(0).SetBytes(serialBytes)

	mtcaid, err := reloid.FromString(mc.CertProfile.MTCAID)
	if err != nil {
		return nil, fmt.Errorf("invalid mtcaid relative oid: %w", err)
	}
	subject := mtcaSubject(mtcaid)
	skid := mtcaid.Bytes()

	notBefore, err := time.Parse(time.DateTime, mc.CertProfile.NotBefore)
	if err != nil {
		return nil, fmt.Errorf("invalid not-before: %w", err)
	}
	notAfter, err := time.Parse(time.DateTime, mc.CertProfile.NotAfter)
	if err != nil {
		return nil, fmt.Errorf("invalid not-after: %w", err)
	}
	if notBefore.After(notAfter) {
		return nil, fmt.Errorf("not-before is after not-after")
	}
	if notAfter.Add(time.Second).Sub(notBefore) > 3660*24*time.Hour {
		return nil, fmt.Errorf("validity period is more than 3660 days (approximately 10 years)")
	}

	prefixUrl, err := url.Parse(mc.CertProfile.TlogPrefix)
	if err != nil {
		return nil, fmt.Errorf("invalid tlog-prefix url: %w", err)
	}
	if prefixUrl.Scheme != "https" {
		return nil, fmt.Errorf("tlog-prefix must be an https:// url, got %q", prefixUrl.Scheme)
	}
	tlogPrefixExtn, err := tlogPrefixExtension(mc.CertProfile.TlogPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tlog prefix extension: %w", err)
	}

	mtcaExtn, err := mtcaExtension()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal MTCA extension: %w", err)
	}

	template := &x509.Certificate{
		// All fields which are respected by x509.CreateCertificate, per
		// https://pkg.go.dev/crypto/x509@go1.27.3#CreateCertificate
		//
		// AuthorityKeyId
		BasicConstraintsValid: true,
		// CRLDistributionPoints
		// DNSNames
		// EmailAddresses
		// ExcludedDNSDomains
		// ExcludedEmailAddresses
		// ExcludedIPRanges
		// ExcludedURIDomains
		// ExtKeyUsage
		ExtraExtensions: []pkix.Extension{mtcaExtn, tlogPrefixExtn},
		// IPAddresses
		IsCA: true,
		// IssuingCertificateURL
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		// MaxPathLen
		MaxPathLenZero: true,
		NotAfter:       notAfter,
		NotBefore:      notBefore,
		// OCSPServer
		// PermittedDNSDomains
		// PermittedDNSDomainsCritical
		// PermittedEmailAddresses
		// PermittedIPRanges
		// PermittedURIDomains
		// PolicyIdentifiers
		// Policies
		SerialNumber: serial,
		// SignatureAlgorithm
		Subject:      subject,
		SubjectKeyId: skid,
		// URIs
		// UnknownExtKeyUsage
	}
	return template, nil
}

// mtcaSubject constructs the Subject field of an MTCA from its MTCA Relative OID.
func mtcaSubject(relativeOID *reloid.RelativeOID) pkix.Name {
	// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-certification-authority-ide
	// A CA ID determines a PKIX distinguished name (Section 4.1.2.4 of [RFC5280]) that can be used in the issuer or subject field of an X.509 TBSCertificate.
	// This distinguished name has a single relative distinguished name, which has a single attribute. The attribute has type id-rdna-trustAnchorID, defined below:
	// 	id-rdna-trustAnchorID OBJECT IDENTIFIER ::= {
	// 			iso(1) identified-organization(3) dod(6) internet(1) security(5)
	// 			mechanisms(5) pkix(7) rdna(25) 3 }
	idRDNATrustAnchorID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 25, 3}

	// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-certification-authority-ide
	// The attribute's value is a RELATIVE-OID containing the trust anchor ID's ASN.1 representation.
	//
	// https://www.itu.int/itu-t/recommendations/rec.aspx?rec=x.680
	// 33.2 This type has a tag which is universal class, number 13.
	tagRelativeOID := 13

	attributes := []pkix.AttributeTypeAndValue{
		{
			Type:  idRDNATrustAnchorID,
			Value: asn1.RawValue{Tag: tagRelativeOID, Bytes: relativeOID.Bytes()},
		},
	}

	return pkix.Name{
		ExtraNames: attributes,
	}
}

func mtcaExtension() (pkix.Extension, error) {
	// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.5
	// This document defines one extension type, id-pe-mtcCertificationAuthority-SHA256, which indicates hashing with SHA-256.
	// Other documents MAY define corresponding extensions for other hash functions or new versions of the tree construction.
	//
	// id-pe-mtcCertificationAuthority-SHA256 OBJECT IDENTIFIER ::= {
	//     iso(1) identified-organization(3) dod(6) internet(1) security(5)
	//     mechanisms(5) pkix(7) pe(1) 38 }
	//
	// ext-mtcCertificationAuthority-SHA256 EXTENSION ::= {
	//     SYNTAX MTCCertificationAuthority
	//     IDENTIFIED BY id-pe-mtcCertificationAuthority-SHA256
	//     CRITICALITY TRUE
	// }
	//
	// -- This is 2^48, the minimum possible serial number in this protocol.
	// mtcMinSerial INTEGER ::= 281474976710656
	//
	// -- This is 2^64-1, the maximum possible serial number in this protocol.
	// mtcMaxSerial INTEGER ::= 18446744073709551615
	//
	// MTCCertificationAuthority ::= SEQUENCE {
	//     sigAlg    AlgorithmIdentifier{SIGNATURE-ALGORITHM, {...}},
	//     minSerial INTEGER (mtcMinSerial..mtcMaxSerial),
	//     maxSerial INTEGER (mtcMinSerial..mtcMaxSerial)
	// }
	extnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 38}

	// https://www.rfc-editor.org/info/rfc9881/
	oidSignatureMLDSA44 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}

	extnMarshaled, err := asn1.Marshal(struct {
		SigAlg    pkix.AlgorithmIdentifier
		MinSerial int64
		MaxSerial int64
	}{
		SigAlg:    pkix.AlgorithmIdentifier{Algorithm: oidSignatureMLDSA44},
		MinSerial: 281474976710656,  // (1<<48), the zeroth serial in log number 1
		MaxSerial: 1688849860263935, // (6<<48)-1, the last serial in log number 5
	})

	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       extnOID,
		Critical: true,
		Value:    extnMarshaled,
	}, nil
}

// tlogPrefixExtension returns the extension containing the CA prefix URL.
//
// https://c2sp.org/mtc-tlog#parameters
//
//	id-mtcTlogPrefixURL OBJECT IDENTIFIER ::= {
//	    iso(1) org(3) dod(6) internet(1) private(4) enterprise(1) C2SP(64829)
//	    mtc-tlog(2) 2 }
//
// MTCTlogPrefixURLs ::= SEQUENCE SIZE (1..MAX) OF IA5String
//
//	ext-mtcTlogPrefixURLs EXTENSION ::= {
//	    SYNTAX MTCTlogPrefixURLs
//	    IDENTIFIED BY id-mtcTlogPrefixURLs
//	    CRITICALITY FALSE
//	}
func tlogPrefixExtension(url string) (pkix.Extension, error) {
	extn := cryptobyte.NewBuilder(nil)
	extn.AddASN1(casn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(casn1.IA5String, func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(url))
		})
	})
	extnBytes, err := extn.Bytes()
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 64829, 2, 2},
		Critical: false,
		Value:    extnBytes,
	}, nil
}
