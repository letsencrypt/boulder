// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package x509 parses X.509-encoded keys and certificates.
package x509

import (
	// all of the hash libraries need to be imported for side-effects,
	// so that crypto.RegisterHash is called
	_ "crypto/md5"
	"crypto/sha256"
	_ "crypto/sha512"
	"strings"

	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"time"

	"github.com/weppos/publicsuffix-go/publicsuffix"
	"github.com/zmap/zcrypto/x509/ct"
	"github.com/zmap/zcrypto/x509/pkix"
)

// ParsedDomainName is a structure holding a parsed domain name (CommonName or DNS SAN) and a parsing error.
type ParsedDomainName struct {
	DomainString string
	ParsedDomain *publicsuffix.DomainName
	ParseError   error
}

func marshalPublicKey(pub interface{}) (publicKeyBytes []byte, publicKeyAlgorithm pkix.AlgorithmIdentifier, err error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(pkcs1PublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, pkix.AlgorithmIdentifier{}, err
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyRSA
		// This is a NULL parameters value which is required by
		// https://tools.ietf.org/html/rfc3279#section-2.3.1.
		publicKeyAlgorithm.Parameters = asn1.NullRawValue
	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		oid, ok := oidFromNamedCurve(pub.Curve)
		if !ok {
			return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: unsupported elliptic curve")
		}
		publicKeyAlgorithm.Algorithm = oidPublicKeyECDSA
		var paramBytes []byte
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return
		}
		publicKeyAlgorithm.Parameters.FullBytes = paramBytes
	case *AugmentedECDSA:
		return marshalPublicKey(pub.Pub)
	default:
		return nil, pkix.AlgorithmIdentifier{}, errors.New("x509: only RSA and ECDSA public keys supported")
	}

	return publicKeyBytes, publicKeyAlgorithm, nil
}

// These structures reflect the ASN.1 structure of X.509 certificates.:

type AugmentedECDSA struct {
	Pub *ecdsa.PublicKey
	Raw asn1.BitString
}

type SignatureAlgorithmOID asn1.ObjectIdentifier

const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA
	DSA
	ECDSA
	total_key_algorithms
)

var keyAlgorithmNames = []string{
	"unknown_algorithm",
	"RSA",
	"DSA",
	"ECDSA",
}

func maxValidationLevel(a, b CertValidationLevel) CertValidationLevel {
	if a > b {
		return a
	}
	return b
}

func getMaxCertValidationLevel(oids []asn1.ObjectIdentifier) CertValidationLevel {
	maxOID := UnknownValidationLevel
	for _, oid := range oids {
		if _, ok := ExtendedValidationOIDs[oid.String()]; ok {
			return EV
		} else if _, ok := OrganizationValidationOIDs[oid.String()]; ok {
			maxOID = maxValidationLevel(maxOID, OV)
		} else if _, ok := DomainValidationOIDs[oid.String()]; ok {
			maxOID = maxValidationLevel(maxOID, DV)
		}
	}
	return maxOID
}

// TODO: slight differences in case in some names. Should be easy to align with stdlib.
// leaving for now to not break compatibility

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var extKeyUsageOIDs = []struct {
	extKeyUsage ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{ExtKeyUsageAny, oidExtKeyUsageAny},
	{ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	//{ExtKeyUsageIPSECEndSystem, oidExtKeyUsageIPSECEndSystem},
	{ExtKeyUsageIpsecUser, oidExtKeyUsageIpsecEndSystem},
	//{ExtKeyUsageIPSECTunnel, oidExtKeyUsageIPSECTunnel},
	{ExtKeyUsageIpsecTunnel, oidExtKeyUsageIpsecTunnel},
	//{ExtKeyUsageIPSECUser, oidExtKeyUsageIPSECUser},
	{ExtKeyUsageIpsecUser, oidExtKeyUsageIpsecUser},
	{ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	//{ExtKeyUsageOCSPSigning, oidExtKeyUsageOCSPSigning},
	{ExtKeyUsageOcspSigning, oidExtKeyUsageOcspSigning},
	{ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
}

// TODO: slight differences in case in some names. Should be easy to align with stdlib.
// leaving for now to not break compatibility

// extKeyUsageOIDs contains the mapping between an ExtKeyUsage and its OID.
var nativeExtKeyUsageOIDs = []struct {
	extKeyUsage ExtKeyUsage
	oid         asn1.ObjectIdentifier
}{
	{ExtKeyUsageAny, oidExtKeyUsageAny},
	{ExtKeyUsageServerAuth, oidExtKeyUsageServerAuth},
	{ExtKeyUsageClientAuth, oidExtKeyUsageClientAuth},
	{ExtKeyUsageCodeSigning, oidExtKeyUsageCodeSigning},
	{ExtKeyUsageEmailProtection, oidExtKeyUsageEmailProtection},
	{ExtKeyUsageIpsecEndSystem, oidExtKeyUsageIpsecEndSystem},
	{ExtKeyUsageIpsecTunnel, oidExtKeyUsageIpsecTunnel},
	{ExtKeyUsageIpsecUser, oidExtKeyUsageIpsecUser},
	{ExtKeyUsageTimeStamping, oidExtKeyUsageTimeStamping},
	{ExtKeyUsageOcspSigning, oidExtKeyUsageOcspSigning},
	{ExtKeyUsageMicrosoftServerGatedCrypto, oidExtKeyUsageMicrosoftServerGatedCrypto},
	{ExtKeyUsageNetscapeServerGatedCrypto, oidExtKeyUsageNetscapeServerGatedCrypto},
}

func extKeyUsageFromOID(oid asn1.ObjectIdentifier) (eku ExtKeyUsage, ok bool) {
	s := oid.String()
	eku, ok = ekuConstants[s]
	return
}

func oidFromExtKeyUsage(eku ExtKeyUsage) (oid asn1.ObjectIdentifier, ok bool) {
	for _, pair := range nativeExtKeyUsageOIDs {
		if eku == pair.extKeyUsage {
			return pair.oid, true
		}
	}
	return
}

// A Certificate represents an X.509 certificate.
type Certificate struct {
	Raw                     []byte // Complete ASN.1 DER content (certificate, signature algorithm and signature).
	RawTBSCertificate       []byte // Certificate part of raw ASN.1 DER content.
	RawSubjectPublicKeyInfo []byte // DER encoded SubjectPublicKeyInfo.
	RawSubject              []byte // DER encoded Subject
	RawIssuer               []byte // DER encoded Issuer

	Signature          []byte
	SignatureAlgorithm SignatureAlgorithm

	SelfSigned bool

	SignatureAlgorithmOID asn1.ObjectIdentifier

	PublicKeyAlgorithm PublicKeyAlgorithm
	PublicKey          interface{}

	PublicKeyAlgorithmOID asn1.ObjectIdentifier

	Version             int
	SerialNumber        *big.Int
	Issuer              pkix.Name
	Subject             pkix.Name
	NotBefore, NotAfter time.Time // Validity bounds.
	ValidityPeriod      int
	KeyUsage            KeyUsage

	IssuerUniqueId  asn1.BitString
	SubjectUniqueId asn1.BitString

	// Extensions contains raw X.509 extensions. When parsing certificates,
	// this can be used to extract non-critical extensions that are not
	// parsed by this package. When marshaling certificates, the Extensions
	// field is ignored, see ExtraExtensions.
	Extensions []pkix.Extension

	// ExtraExtensions contains extensions to be copied, raw, into any
	// marshaled certificates. Values override any extensions that would
	// otherwise be produced based on the other fields. The ExtraExtensions
	// field is not populated when parsing certificates, see Extensions.
	ExtraExtensions []pkix.Extension

	// UnhandledCriticalExtensions contains a list of extension IDs that
	// were not (fully) processed when parsing. Verify will fail if this
	// slice is non-empty, unless verification is delegated to an OS
	// library which understands all the critical extensions.
	//
	// Users can access these extensions using Extensions and can remove
	// elements from this slice if they believe that they have been
	// handled.
	UnhandledCriticalExtensions []asn1.ObjectIdentifier

	ExtKeyUsage        []ExtKeyUsage           // Sequence of extended key usages.
	UnknownExtKeyUsage []asn1.ObjectIdentifier // Encountered extended key usages unknown to this package.

	BasicConstraintsValid bool // if true then the next two fields are valid.
	IsCA                  bool

	// MaxPathLen and MaxPathLenZero indicate the presence and
	// value of the BasicConstraints' "pathLenConstraint".
	//
	// When parsing a certificate, a positive non-zero MaxPathLen
	// means that the field was specified, -1 means it was unset,
	// and MaxPathLenZero being true mean that the field was
	// explicitly set to zero. The case of MaxPathLen==0 with MaxPathLenZero==false
	// should be treated equivalent to -1 (unset).
	//
	// When generating a certificate, an unset pathLenConstraint
	// can be requested with either MaxPathLen == -1 or using the
	// zero value for both MaxPathLen and MaxPathLenZero.
	MaxPathLen int
	// MaxPathLenZero indicates that BasicConstraintsValid==true and
	// MaxPathLen==0 should be interpreted as an actual Max path length
	// of zero. Otherwise, that combination is interpreted as MaxPathLen
	// not being set.
	MaxPathLenZero bool

	SubjectKeyId   []byte
	AuthorityKeyId []byte

	// RFC 5280, 4.2.2.1 (Authority Information Access)
	OCSPServer            []string
	IssuingCertificateURL []string

	// Subject Alternate Name values
	OtherNames     []pkix.OtherName
	DNSNames       []string
	EmailAddresses []string
	DirectoryNames []pkix.Name
	EDIPartyNames  []pkix.EDIPartyName
	URIs           []string
	IPAddresses    []net.IP
	RegisteredIDs  []asn1.ObjectIdentifier

	// Issuer Alternative Name values
	IANOtherNames     []pkix.OtherName
	IANDNSNames       []string
	IANEmailAddresses []string
	IANDirectoryNames []pkix.Name
	IANEDIPartyNames  []pkix.EDIPartyName
	IANURIs           []string
	IANIPAddresses    []net.IP
	IANRegisteredIDs  []asn1.ObjectIdentifier

	// Certificate Policies values
	QualifierId          [][]asn1.ObjectIdentifier
	CPSuri               [][]string
	ExplicitTexts        [][]asn1.RawValue
	NoticeRefOrgnization [][]asn1.RawValue
	NoticeRefNumbers     [][]NoticeNumber

	ParsedExplicitTexts         [][]string
	ParsedNoticeRefOrganization [][]string

	// Name constraints
	NameConstraintsCritical bool // if true then the name constraints are marked critical.
	PermittedDNSNames       []GeneralSubtreeString
	ExcludedDNSNames        []GeneralSubtreeString
	PermittedEmailAddresses []GeneralSubtreeString
	ExcludedEmailAddresses  []GeneralSubtreeString
	PermittedIPAddresses    []GeneralSubtreeIP
	ExcludedIPAddresses     []GeneralSubtreeIP
	PermittedDirectoryNames []GeneralSubtreeName
	ExcludedDirectoryNames  []GeneralSubtreeName
	PermittedEdiPartyNames  []GeneralSubtreeEdi
	ExcludedEdiPartyNames   []GeneralSubtreeEdi
	PermittedRegisteredIDs  []GeneralSubtreeOid
	ExcludedRegisteredIDs   []GeneralSubtreeOid
	PermittedX400Addresses  []GeneralSubtreeRaw
	ExcludedX400Addresses   []GeneralSubtreeRaw

	// CRL Distribution Points
	CRLDistributionPoints []string

	PolicyIdentifiers []asn1.ObjectIdentifier
	ValidationLevel   CertValidationLevel

	// Fingerprints
	FingerprintMD5    CertificateFingerprint
	FingerprintSHA1   CertificateFingerprint
	FingerprintSHA256 CertificateFingerprint
	FingerprintNoCT   CertificateFingerprint

	// SPKI
	SPKIFingerprint           CertificateFingerprint
	SPKISubjectFingerprint    CertificateFingerprint
	TBSCertificateFingerprint CertificateFingerprint

	IsPrecert bool

	// Internal
	validSignature bool

	// CT
	SignedCertificateTimestampList []*ct.SignedCertificateTimestamp

	// Used to speed up the zlint checks. Populated by the GetParsedDNSNames method.
	parsedDNSNames []ParsedDomainName
	// Used to speed up the zlint checks. Populated by the GetParsedCommonName method
	parsedCommonName *ParsedDomainName
}

// SubjectAndKey represents a (subjecty, subject public key info) tuple.
type SubjectAndKey struct {
	RawSubject              []byte
	RawSubjectPublicKeyInfo []byte
	Fingerprint             CertificateFingerprint
	PublicKey               interface{}
	PublicKeyAlgorithm      PublicKeyAlgorithm
}

type NoticeNumber []int

type GeneralSubtreeString struct {
	Data string
	Max  int
	Min  int
}

type GeneralSubtreeIP struct {
	Data net.IPNet
	Max  int
	Min  int
}

type GeneralSubtreeName struct {
	Data pkix.Name
	Max  int
	Min  int
}

type GeneralSubtreeEdi struct {
	Data pkix.EDIPartyName
	Max  int
	Min  int
}

type GeneralSubtreeOid struct {
	Data asn1.ObjectIdentifier
	Max  int
	Min  int
}

type GeneralSubtreeRaw struct {
	Data asn1.RawValue
	Max  int
	Min  int
}

// SubjectAndKey returns a SubjectAndKey for this certificate.
func (c *Certificate) SubjectAndKey() *SubjectAndKey {
	return &SubjectAndKey{
		RawSubject:              c.RawSubject,
		RawSubjectPublicKeyInfo: c.RawSubjectPublicKeyInfo,
		Fingerprint:             c.SPKISubjectFingerprint,
		PublicKey:               c.PublicKey,
		PublicKeyAlgorithm:      c.PublicKeyAlgorithm,
	}
}

// CheckSignatureFrom verifies that the signature on c is a valid signature
// from parent.
func (c *Certificate) CheckSignatureFrom(parent *Certificate) (err error) {
	// RFC 5280, 4.2.1.9:
	// "If the basic constraints extension is not present in a version 3
	// certificate, or the extension is present but the cA boolean is not
	// asserted, then the certified public key MUST NOT be used to verify
	// certificate signatures."
	// (except for Entrust, see comment above entrustBrokenSPKI)
	if (parent.Version == 3 && !parent.BasicConstraintsValid ||
		parent.BasicConstraintsValid && !parent.IsCA) &&
		!bytes.Equal(c.RawSubjectPublicKeyInfo, entrustBrokenSPKI) {
		return ConstraintViolationError{}
	}

	if parent.KeyUsage != 0 && parent.KeyUsage&KeyUsageCertSign == 0 {
		return ConstraintViolationError{}
	}

	if parent.PublicKeyAlgorithm == UnknownPublicKeyAlgorithm {
		return ErrUnsupportedAlgorithm
	}

	// TODO(agl): don't ignore the path length constraint.

	if !bytes.Equal(parent.RawSubject, c.RawIssuer) {
		return errors.New("Mis-match issuer/subject")
	}

	return parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
}

func CheckSignatureFromKey(publicKey interface{}, algo SignatureAlgorithm, signed, signature []byte) (err error) {
	var hashType crypto.Hash

	switch algo {
	// NOTE: exception to stdlib, allow MD5 algorithm
	case MD5WithRSA:
		hashType = crypto.MD5
	case SHA1WithRSA, DSAWithSHA1, ECDSAWithSHA1:
		hashType = crypto.SHA1
	case SHA256WithRSA, SHA256WithRSAPSS, DSAWithSHA256, ECDSAWithSHA256:
		hashType = crypto.SHA256
	case SHA384WithRSA, SHA384WithRSAPSS, ECDSAWithSHA384:
		hashType = crypto.SHA384
	case SHA512WithRSA, SHA512WithRSAPSS, ECDSAWithSHA512:
		hashType = crypto.SHA512
	//case MD2WithRSA, MD5WithRSA:
	case MD2WithRSA:
		return InsecureAlgorithmError(algo)
	default:
		return ErrUnsupportedAlgorithm
	}

	if !hashType.Available() {
		return ErrUnsupportedAlgorithm
	}
	h := hashType.New()

	h.Write(signed)
	digest := h.Sum(nil)

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		if algo.isRSAPSS() {
			return rsa.VerifyPSS(pub, hashType, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			return rsa.VerifyPKCS1v15(pub, hashType, digest, signature)
		}
	case *dsa.PublicKey:
		dsaSig := new(dsaSignature)
		if rest, err := asn1.Unmarshal(signature, dsaSig); err != nil {
			return err
		} else if len(rest) != 0 {
			return errors.New("x509: trailing data after DSA signature")
		}
		if dsaSig.R.Sign() <= 0 || dsaSig.S.Sign() <= 0 {
			return errors.New("x509: DSA signature contained zero or negative values")
		}
		if !dsa.Verify(pub, digest, dsaSig.R, dsaSig.S) {
			return errors.New("x509: DSA verification failure")
		}
		return
	case *ecdsa.PublicKey:
		ecdsaSig := new(ecdsaSignature)
		if rest, err := asn1.Unmarshal(signature, ecdsaSig); err != nil {
			return err
		} else if len(rest) != 0 {
			return errors.New("x509: trailing data after ECDSA signature")
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("x509: ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pub, digest, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("x509: ECDSA verification failure")
		}
		return
	case *AugmentedECDSA:
		ecdsaSig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(signature, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("x509: ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pub.Pub, digest, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("x509: ECDSA verification failure")
		}
		return
	}
	return ErrUnsupportedAlgorithm
}

// CheckCRLSignature checks that the signature in crl is from c.
func (c *Certificate) CheckCRLSignature(crl *pkix.CertificateList) error {
	algo := getSignatureAlgorithmFromAI(crl.SignatureAlgorithm)
	return c.CheckSignature(algo, crl.TBSCertList.Raw, crl.SignatureValue.RightAlign())
}

// UnhandledCriticalExtension results when the certificate contains an
// unimplemented X.509 extension marked as critical.
type UnhandledCriticalExtension struct {
	oid     asn1.ObjectIdentifier
	message string
}

func (h UnhandledCriticalExtension) Error() string {
	return fmt.Sprintf("x509: unhandled critical extension: %s | %s", h.oid, h.message)
}

// CheckSignature verifies that signature is a valid signature over signed from
// c's public key.
func (c *Certificate) CheckSignature(algo SignatureAlgorithm, signed, signature []byte) (err error) {
	return CheckSignatureFromKey(c.PublicKey, algo, signed, signature)
}

// TimeInValidityPeriod returns true if NotBefore < t < NotAfter
func (c *Certificate) TimeInValidityPeriod(t time.Time) bool {
	return c.NotBefore.Before(t) && c.NotAfter.After(t)
}

// RFC 5280 4.2.1.4
type policyInformation struct {
	Policy     asn1.ObjectIdentifier
	Qualifiers []policyQualifierInfo `asn1:"optional"`
}

type policyQualifierInfo struct {
	PolicyQualifierId asn1.ObjectIdentifier
	Qualifier         asn1.RawValue
}

type userNotice struct {
	NoticeRef    noticeReference `asn1:"optional"`
	ExplicitText asn1.RawValue   `asn1:"optional"`
}

type noticeReference struct {
	Organization  asn1.RawValue
	NoticeNumbers []int
}

type generalSubtree struct {
	Value asn1.RawValue `asn1:"optional"`
	Min   int           `asn1:"tag:0,default:0,optional"`
	Max   int           `asn1:"tag:1,optional"`
}

func parsePublicKey(algo PublicKeyAlgorithm, keyData *publicKeyInfo) (interface{}, error) {
	asn1Data := keyData.PublicKey.RightAlign()
	switch algo {
	case RSA:

		// TODO: disabled since current behaviour does not expect it. Should be enabled though
		// RSA public keys must have a NULL in the parameters
		// (https://tools.ietf.org/html/rfc3279#section-2.3.1).
		//if !bytes.Equal(keyData.Algorithm.Parameters.FullBytes, asn1.NullBytes) {
		//	return nil, errors.New("x509: RSA key missing NULL parameters")
		//}

		p := new(pkcs1PublicKey)
		rest, err := asn1.Unmarshal(asn1Data, p)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("x509: trailing data after RSA public key")
		}

		if p.N.Sign() <= 0 {
			return nil, errors.New("x509: RSA modulus is not a positive number")
		}
		if p.E <= 0 {
			return nil, errors.New("x509: RSA public exponent is not a positive number")
		}

		pub := &rsa.PublicKey{
			E: p.E,
			N: p.N,
		}
		return pub, nil
	case DSA:
		var p *big.Int
		rest, err := asn1.Unmarshal(asn1Data, &p)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("x509: trailing data after DSA public key")
		}
		paramsData := keyData.Algorithm.Parameters.FullBytes
		params := new(dsaAlgorithmParameters)
		rest, err = asn1.Unmarshal(paramsData, params)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("x509: trailing data after DSA parameters")
		}
		if p.Sign() <= 0 || params.P.Sign() <= 0 || params.Q.Sign() <= 0 || params.G.Sign() <= 0 {
			return nil, errors.New("x509: zero or negative DSA parameter")
		}
		pub := &dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: params.P,
				Q: params.Q,
				G: params.G,
			},
			Y: p,
		}
		return pub, nil
	case ECDSA:
		paramsData := keyData.Algorithm.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("x509: trailing data after ECDSA parameters")
		}
		namedCurve := namedCurveFromOID(*namedCurveOID)
		if namedCurve == nil {
			return nil, errors.New("x509: unsupported elliptic curve")
		}
		x, y := elliptic.Unmarshal(namedCurve, asn1Data)
		if x == nil {
			return nil, errors.New("x509: failed to unmarshal elliptic curve point")
		}
		key := &ecdsa.PublicKey{
			Curve: namedCurve,
			X:     x,
			Y:     y,
		}

		pub := &AugmentedECDSA{
			Pub: key,
			Raw: keyData.PublicKey,
		}
		return pub, nil
	default:
		return nil, nil
	}
}

func parseGeneralNames(value []byte) (otherNames []pkix.OtherName, dnsNames, emailAddresses, URIs []string, directoryNames []pkix.Name, ediPartyNames []pkix.EDIPartyName, ipAddresses []net.IP, registeredIDs []asn1.ObjectIdentifier, err error) {
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	if _, err = asn1.Unmarshal(value, &seq); err != nil {
		return
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		err = asn1.StructuralError{Msg: "bad SAN sequence"}
		return
	}

	rest := seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return
		}
		switch v.Tag {
		case 0:
			var oName pkix.OtherName
			_, err = asn1.UnmarshalWithParams(v.FullBytes, &oName, "tag:0")
			if err != nil {
				return
			}
			otherNames = append(otherNames, oName)
		case 1:
			emailAddresses = append(emailAddresses, string(v.Bytes))
		case 2:
			dnsNames = append(dnsNames, string(v.Bytes))
		case 4:
			var rdn pkix.RDNSequence
			_, err = asn1.Unmarshal(v.Bytes, &rdn)
			if err != nil {
				return
			}
			var dir pkix.Name
			dir.FillFromRDNSequence(&rdn)
			directoryNames = append(directoryNames, dir)
		case 5:
			var ediName pkix.EDIPartyName
			_, err = asn1.UnmarshalWithParams(v.FullBytes, &ediName, "tag:5")
			if err != nil {
				return
			}
			ediPartyNames = append(ediPartyNames, ediName)
		case 6:
			URIs = append(URIs, string(v.Bytes))
		case 7:
			switch len(v.Bytes) {
			case net.IPv4len, net.IPv6len:
				ipAddresses = append(ipAddresses, v.Bytes)
			default:
				err = errors.New("x509: certificate contained IP address of length " + strconv.Itoa(len(v.Bytes)))
				return
			}
		case 8:
			var id asn1.ObjectIdentifier
			_, err = asn1.UnmarshalWithParams(v.FullBytes, &id, "tag:8")
			if err != nil {
				return
			}
			registeredIDs = append(registeredIDs, id)
		}
	}

	return
}

//TODO
func parseCertificate(in *certificate) (*Certificate, error) {
	out := new(Certificate)
	out.Raw = in.Raw
	out.RawTBSCertificate = in.TBSCertificate.Raw
	out.RawSubjectPublicKeyInfo = in.TBSCertificate.PublicKey.Raw
	out.RawSubject = in.TBSCertificate.Subject.FullBytes
	out.RawIssuer = in.TBSCertificate.Issuer.FullBytes

	// Fingerprints
	out.FingerprintMD5 = MD5Fingerprint(in.Raw)
	out.FingerprintSHA1 = SHA1Fingerprint(in.Raw)
	out.FingerprintSHA256 = SHA256Fingerprint(in.Raw)
	out.SPKIFingerprint = SHA256Fingerprint(in.TBSCertificate.PublicKey.Raw)
	out.TBSCertificateFingerprint = SHA256Fingerprint(in.TBSCertificate.Raw)

	tbs := in.TBSCertificate
	originalExtensions := in.TBSCertificate.Extensions

	// Blow away the raw data since it also includes CT data
	tbs.Raw = nil

	// remove the CT extensions
	extensions := make([]pkix.Extension, 0, len(originalExtensions))
	for _, extension := range originalExtensions {
		if extension.Id.Equal(oidExtensionCTPrecertificatePoison) {
			continue
		}
		if extension.Id.Equal(oidExtensionSignedCertificateTimestampList) {
			continue
		}
		extensions = append(extensions, extension)
	}

	tbs.Extensions = extensions

	tbsbytes, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, err
	}
	if tbsbytes == nil {
		return nil, asn1.SyntaxError{Msg: "Trailing data"}
	}
	out.FingerprintNoCT = SHA256Fingerprint(tbsbytes[:])

	// Hash both SPKI and Subject to create a fingerprint that we can use to describe a CA
	hasher := sha256.New()
	hasher.Write(in.TBSCertificate.PublicKey.Raw)
	hasher.Write(in.TBSCertificate.Subject.FullBytes)
	out.SPKISubjectFingerprint = hasher.Sum(nil)

	out.Signature = in.SignatureValue.RightAlign()
	out.SignatureAlgorithm =
		getSignatureAlgorithmFromAI(in.TBSCertificate.SignatureAlgorithm)

	out.SignatureAlgorithmOID = in.TBSCertificate.SignatureAlgorithm.Algorithm

	out.PublicKeyAlgorithm =
		getPublicKeyAlgorithmFromOID(in.TBSCertificate.PublicKey.Algorithm.Algorithm)
	out.PublicKey, err = parsePublicKey(out.PublicKeyAlgorithm, &in.TBSCertificate.PublicKey)
	if err != nil {
		return nil, err
	}

	out.PublicKeyAlgorithmOID = in.TBSCertificate.PublicKey.Algorithm.Algorithm
	out.Version = in.TBSCertificate.Version + 1
	out.SerialNumber = in.TBSCertificate.SerialNumber

	var issuer, subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(in.TBSCertificate.Subject.FullBytes, &subject); err != nil {
		return nil, err
	}
	if _, err := asn1.Unmarshal(in.TBSCertificate.Issuer.FullBytes, &issuer); err != nil {
		return nil, err
	}

	out.Issuer.FillFromRDNSequence(&issuer)
	out.Subject.FillFromRDNSequence(&subject)

	// Check if self-signed
	if bytes.Equal(out.RawSubject, out.RawIssuer) {
		// Possibly self-signed, check the signature against itself.
		if err := out.CheckSignature(out.SignatureAlgorithm, out.RawTBSCertificate, out.Signature); err == nil {
			out.SelfSigned = true
		}
	}

	out.NotBefore = in.TBSCertificate.Validity.NotBefore
	out.NotAfter = in.TBSCertificate.Validity.NotAfter

	out.ValidityPeriod = int(out.NotAfter.Sub(out.NotBefore).Seconds())

	out.IssuerUniqueId = in.TBSCertificate.UniqueId
	out.SubjectUniqueId = in.TBSCertificate.SubjectUniqueId

	for _, e := range in.TBSCertificate.Extensions {
		out.Extensions = append(out.Extensions, e)

		if len(e.Id) == 4 && e.Id[0] == 2 && e.Id[1] == 5 && e.Id[2] == 29 {
			switch e.Id[3] {
			case 15:
				// RFC 5280, 4.2.1.3
				var usageBits asn1.BitString
				_, err := asn1.Unmarshal(e.Value, &usageBits)

				if err == nil {
					var usage int
					for i := 0; i < 9; i++ {
						if usageBits.At(i) != 0 {
							usage |= 1 << uint(i)
						}
					}
					out.KeyUsage = KeyUsage(usage)
					continue
				}
			case 19:
				// RFC 5280, 4.2.1.9
				var constraints basicConstraints
				_, err := asn1.Unmarshal(e.Value, &constraints)

				if err == nil {
					out.BasicConstraintsValid = true
					out.IsCA = constraints.IsCA
					out.MaxPathLen = constraints.MaxPathLen
					out.MaxPathLenZero = out.MaxPathLen == 0
					continue
				}
			case 17:
				out.OtherNames, out.DNSNames, out.EmailAddresses, out.URIs, out.DirectoryNames, out.EDIPartyNames, out.IPAddresses, out.RegisteredIDs, err = parseGeneralNames(e.Value)
				if err != nil {
					return nil, err
				}

				if len(out.DNSNames) > 0 || len(out.EmailAddresses) > 0 || len(out.IPAddresses) > 0 {
					continue
				}
				// If we didn't parse any of the names then we
				// fall through to the critical check below.
			case 18:
				out.IANOtherNames, out.IANDNSNames, out.IANEmailAddresses, out.IANURIs, out.IANDirectoryNames, out.IANEDIPartyNames, out.IANIPAddresses, out.IANRegisteredIDs, err = parseGeneralNames(e.Value)
				if err != nil {
					return nil, err
				}

				if len(out.IANDNSNames) > 0 || len(out.IANEmailAddresses) > 0 || len(out.IANIPAddresses) > 0 {
					continue
				}
			case 30:
				// RFC 5280, 4.2.1.10

				// NameConstraints ::= SEQUENCE {
				//      permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
				//      excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
				//
				// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
				//
				// GeneralSubtree ::= SEQUENCE {
				//      base                    GeneralName,
				//      Min         [0]     BaseDistance DEFAULT 0,
				//      Max         [1]     BaseDistance OPTIONAL }
				//
				// BaseDistance ::= INTEGER (0..MAX)

				var constraints nameConstraints
				_, err := asn1.Unmarshal(e.Value, &constraints)
				if err != nil {
					return nil, err
				}

				if e.Critical {
					out.NameConstraintsCritical = true
				}

				for _, subtree := range constraints.Permitted {
					switch subtree.Value.Tag {
					case 1:
						out.PermittedEmailAddresses = append(out.PermittedEmailAddresses, GeneralSubtreeString{Data: string(subtree.Value.Bytes), Max: subtree.Max, Min: subtree.Min})
					case 2:
						out.PermittedDNSNames = append(out.PermittedDNSNames, GeneralSubtreeString{Data: string(subtree.Value.Bytes), Max: subtree.Max, Min: subtree.Min})
					case 3:
						out.PermittedX400Addresses = append(out.PermittedX400Addresses, GeneralSubtreeRaw{Data: subtree.Value, Max: subtree.Max, Min: subtree.Min})
					case 4:
						var rawdn pkix.RDNSequence
						if _, err := asn1.Unmarshal(subtree.Value.Bytes, &rawdn); err != nil {
							return out, err
						}
						var dn pkix.Name
						dn.FillFromRDNSequence(&rawdn)
						out.PermittedDirectoryNames = append(out.PermittedDirectoryNames, GeneralSubtreeName{Data: dn, Max: subtree.Max, Min: subtree.Min})
					case 5:
						var ediName pkix.EDIPartyName
						_, err = asn1.UnmarshalWithParams(subtree.Value.FullBytes, &ediName, "tag:5")
						if err != nil {
							return out, err
						}
						out.PermittedEdiPartyNames = append(out.PermittedEdiPartyNames, GeneralSubtreeEdi{Data: ediName, Max: subtree.Max, Min: subtree.Min})
					case 7:
						switch len(subtree.Value.Bytes) {
						case net.IPv4len * 2:
							ip := net.IPNet{IP: subtree.Value.Bytes[:net.IPv4len], Mask: subtree.Value.Bytes[net.IPv4len:]}
							out.PermittedIPAddresses = append(out.PermittedIPAddresses, GeneralSubtreeIP{Data: ip, Max: subtree.Max, Min: subtree.Min})
						case net.IPv6len * 2:
							ip := net.IPNet{IP: subtree.Value.Bytes[:net.IPv6len], Mask: subtree.Value.Bytes[net.IPv6len:]}
							out.PermittedIPAddresses = append(out.PermittedIPAddresses, GeneralSubtreeIP{Data: ip, Max: subtree.Max, Min: subtree.Min})
						default:
							return out, errors.New("x509: certificate name constraint contained IP address range of length " + strconv.Itoa(len(subtree.Value.Bytes)))
						}
					case 8:
						var id asn1.ObjectIdentifier
						_, err = asn1.UnmarshalWithParams(subtree.Value.FullBytes, &id, "tag:8")
						if err != nil {
							return out, err
						}
						out.PermittedRegisteredIDs = append(out.PermittedRegisteredIDs, GeneralSubtreeOid{Data: id, Max: subtree.Max, Min: subtree.Min})
					}
				}
				for _, subtree := range constraints.Excluded {
					switch subtree.Value.Tag {
					case 1:
						out.ExcludedEmailAddresses = append(out.ExcludedEmailAddresses, GeneralSubtreeString{Data: string(subtree.Value.Bytes), Max: subtree.Max, Min: subtree.Min})
					case 2:
						out.ExcludedDNSNames = append(out.ExcludedDNSNames, GeneralSubtreeString{Data: string(subtree.Value.Bytes), Max: subtree.Max, Min: subtree.Min})
					case 3:
						out.ExcludedX400Addresses = append(out.ExcludedX400Addresses, GeneralSubtreeRaw{Data: subtree.Value, Max: subtree.Max, Min: subtree.Min})
					case 4:
						var rawdn pkix.RDNSequence
						if _, err := asn1.Unmarshal(subtree.Value.Bytes, &rawdn); err != nil {
							return out, err
						}
						var dn pkix.Name
						dn.FillFromRDNSequence(&rawdn)
						out.ExcludedDirectoryNames = append(out.ExcludedDirectoryNames, GeneralSubtreeName{Data: dn, Max: subtree.Max, Min: subtree.Min})
					case 5:
						var ediName pkix.EDIPartyName
						_, err = asn1.Unmarshal(subtree.Value.Bytes, &ediName)
						if err != nil {
							return out, err
						}
						out.ExcludedEdiPartyNames = append(out.ExcludedEdiPartyNames, GeneralSubtreeEdi{Data: ediName, Max: subtree.Max, Min: subtree.Min})
					case 7:
						switch len(subtree.Value.Bytes) {
						case net.IPv4len * 2:
							ip := net.IPNet{IP: subtree.Value.Bytes[:net.IPv4len], Mask: subtree.Value.Bytes[net.IPv4len:]}
							out.ExcludedIPAddresses = append(out.ExcludedIPAddresses, GeneralSubtreeIP{Data: ip, Max: subtree.Max, Min: subtree.Min})
						case net.IPv6len * 2:
							ip := net.IPNet{IP: subtree.Value.Bytes[:net.IPv6len], Mask: subtree.Value.Bytes[net.IPv6len:]}
							out.ExcludedIPAddresses = append(out.ExcludedIPAddresses, GeneralSubtreeIP{Data: ip, Max: subtree.Max, Min: subtree.Min})
						default:
							return out, errors.New("x509: certificate name constraint contained IP address range of length " + strconv.Itoa(len(subtree.Value.Bytes)))
						}
					case 8:
						var id asn1.ObjectIdentifier
						_, err = asn1.Unmarshal(subtree.Value.Bytes, &id)
						if err != nil {
							return out, err
						}
						out.ExcludedRegisteredIDs = append(out.ExcludedRegisteredIDs, GeneralSubtreeOid{Data: id, Max: subtree.Max, Min: subtree.Min})
					}
				}
				continue

			case 31:
				// RFC 5280, 4.2.1.14

				// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
				//
				// DistributionPoint ::= SEQUENCE {
				//     distributionPoint       [0]     DistributionPointName OPTIONAL,
				//     reasons                 [1]     ReasonFlags OPTIONAL,
				//     cRLIssuer               [2]     GeneralNames OPTIONAL }
				//
				// DistributionPointName ::= CHOICE {
				//     fullName                [0]     GeneralNames,
				//     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

				var cdp []distributionPoint
				_, err := asn1.Unmarshal(e.Value, &cdp)
				if err != nil {
					return nil, err
				}

				for _, dp := range cdp {
					// Per RFC 5280, 4.2.1.13, one of distributionPoint or cRLIssuer may be empty.
					if len(dp.DistributionPoint.FullName.Bytes) == 0 {
						continue
					}

					var n asn1.RawValue
					dpName := dp.DistributionPoint.FullName.Bytes
					// FullName is a GeneralNames, which is a SEQUENCE OF
					// GeneralName, which in turn is a CHOICE.
					// Per https://www.ietf.org/rfc/rfc5280.txt, multiple names
					// for a single DistributionPoint give different pointers to
					// the same CRL.
					for len(dpName) > 0 {
						dpName, err = asn1.Unmarshal(dpName, &n)
						if err != nil {
							return nil, err
						}
						if n.Tag == 6 {
							out.CRLDistributionPoints = append(out.CRLDistributionPoints, string(n.Bytes))
						}
					}
				}
				continue

			case 35:
				// RFC 5280, 4.2.1.1
				var a authKeyId
				_, err = asn1.Unmarshal(e.Value, &a)
				if err != nil {
					return nil, err
				}
				out.AuthorityKeyId = a.Id
				continue

			case 37:
				// RFC 5280, 4.2.1.12.  Extended Key Usage

				// id-ce-extKeyUsage OBJECT IDENTIFIER ::= { id-ce 37 }
				//
				// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
				//
				// KeyPurposeId ::= OBJECT IDENTIFIER

				var keyUsage []asn1.ObjectIdentifier
				_, err = asn1.Unmarshal(e.Value, &keyUsage)
				if err != nil {
					return nil, err
				}

				for _, u := range keyUsage {
					if extKeyUsage, ok := extKeyUsageFromOID(u); ok {
						out.ExtKeyUsage = append(out.ExtKeyUsage, extKeyUsage)
					} else {
						out.UnknownExtKeyUsage = append(out.UnknownExtKeyUsage, u)
					}
				}

				continue

			case 14:
				// RFC 5280, 4.2.1.2
				var keyid []byte
				_, err = asn1.Unmarshal(e.Value, &keyid)
				if err != nil {
					return nil, err
				}
				out.SubjectKeyId = keyid
				continue

			case 32:
				// RFC 5280 4.2.1.4: Certificate Policies
				var policies []policyInformation
				if _, err = asn1.Unmarshal(e.Value, &policies); err != nil {
					return nil, err
				}
				out.PolicyIdentifiers = make([]asn1.ObjectIdentifier, len(policies))
				out.QualifierId = make([][]asn1.ObjectIdentifier, len(policies))
				out.ExplicitTexts = make([][]asn1.RawValue, len(policies))
				out.NoticeRefOrgnization = make([][]asn1.RawValue, len(policies))
				out.NoticeRefNumbers = make([][]NoticeNumber, len(policies))
				out.ParsedExplicitTexts = make([][]string, len(policies))
				out.ParsedNoticeRefOrganization = make([][]string, len(policies))
				out.CPSuri = make([][]string, len(policies))

				for i, policy := range policies {
					out.PolicyIdentifiers[i] = policy.Policy
					// parse optional Qualifier for zlint
					for _, qualifier := range policy.Qualifiers {
						out.QualifierId[i] = append(out.QualifierId[i], qualifier.PolicyQualifierId)
						userNoticeOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 2}
						cpsURIOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 2, 1}
						if qualifier.PolicyQualifierId.Equal(userNoticeOID) {
							var un userNotice
							if _, err = asn1.Unmarshal(qualifier.Qualifier.FullBytes, &un); err != nil {
								return nil, err
							}
							if len(un.ExplicitText.Bytes) != 0 {
								out.ExplicitTexts[i] = append(out.ExplicitTexts[i], un.ExplicitText)
								out.ParsedExplicitTexts[i] = append(out.ParsedExplicitTexts[i], string(un.ExplicitText.Bytes))
							}
							if un.NoticeRef.Organization.Bytes != nil || un.NoticeRef.NoticeNumbers != nil {
								out.NoticeRefOrgnization[i] = append(out.NoticeRefOrgnization[i], un.NoticeRef.Organization)
								out.NoticeRefNumbers[i] = append(out.NoticeRefNumbers[i], un.NoticeRef.NoticeNumbers)
								out.ParsedNoticeRefOrganization[i] = append(out.ParsedNoticeRefOrganization[i], string(un.NoticeRef.Organization.Bytes))
							}
						}
						if qualifier.PolicyQualifierId.Equal(cpsURIOID) {
							var cpsURIRaw asn1.RawValue
							if _, err = asn1.Unmarshal(qualifier.Qualifier.FullBytes, &cpsURIRaw); err != nil {
								return nil, err
							}
							out.CPSuri[i] = append(out.CPSuri[i], string(cpsURIRaw.Bytes))
						}
					}
				}
				if out.SelfSigned {
					out.ValidationLevel = UnknownValidationLevel
				} else {
					// See http://unmitigatedrisk.com/?p=203
					validationLevel := getMaxCertValidationLevel(out.PolicyIdentifiers)
					if validationLevel == UnknownValidationLevel {
						if (len(out.Subject.Organization) > 0 && out.Subject.Organization[0] == out.Subject.CommonName) || (len(out.Subject.OrganizationalUnit) > 0 && strings.Contains(out.Subject.OrganizationalUnit[0], "Domain Control Validated")) {
							if len(out.Subject.Locality) == 0 && len(out.Subject.Province) == 0 && len(out.Subject.PostalCode) == 0 {
								validationLevel = DV
							}
						} else if len(out.Subject.Organization) > 0 && out.Subject.Organization[0] == "Persona Not Validated" && strings.Contains(out.Issuer.CommonName, "StartCom") {
							validationLevel = DV
						}
					}
					out.ValidationLevel = validationLevel
				}
			}
		} else if e.Id.Equal(oidExtensionAuthorityInfoAccess) {
			// RFC 5280 4.2.2.1: Authority Information Access
			var aia []authorityInfoAccess
			if _, err = asn1.Unmarshal(e.Value, &aia); err != nil {
				return nil, err
			}

			for _, v := range aia {
				// GeneralName: uniformResourceIdentifier [6] IA5String
				if v.Location.Tag != 6 {
					continue
				}
				if v.Method.Equal(oidAuthorityInfoAccessOcsp) {
					out.OCSPServer = append(out.OCSPServer, string(v.Location.Bytes))
				} else if v.Method.Equal(oidAuthorityInfoAccessIssuers) {
					out.IssuingCertificateURL = append(out.IssuingCertificateURL, string(v.Location.Bytes))
				}
			}
		} else if e.Id.Equal(oidExtensionSignedCertificateTimestampList) {
			// SignedCertificateTimestamp
			//var scts asn1.RawValue
			var scts []byte
			if _, err = asn1.Unmarshal(e.Value, &scts); err != nil {
				return nil, err
			}
			// ignore length of
			if len(scts) < 2 {
				return nil, errors.New("malformed SCT extension: length field")
			}
			scts = scts[2:]
			for len(scts) > 0 {
				length := int(scts[1]) + (int(scts[0]) << 8)
				if (length + 2) > len(scts) {
					return nil, errors.New("malformed SCT extension: incomplete SCT")
				}
				sct, err := ct.DeserializeSCT(bytes.NewReader(scts[2 : length+2]))
				if err != nil {
					return nil, err
				}
				scts = scts[2+length:]
				out.SignedCertificateTimestampList = append(out.SignedCertificateTimestampList, sct)
			}
		} else if e.Id.Equal(oidExtensionCTPrecertificatePoison) {
			if e.Value[0] == 5 && e.Value[1] == 0 {
				out.IsPrecert = true
				continue
			} else {
				return nil, UnhandledCriticalExtension{e.Id, "Malformed precert poison"}
			}
		}

		//if e.Critical {
		//	return out, UnhandledCriticalExtension{e.Id}
		//}
	}

	return out, nil
}

func ParseTBSCertificate(asn1Data []byte) (*Certificate, error) {
	var tbsCert tbsCertificate
	rest, err := asn1.Unmarshal(asn1Data, &tbsCert)
	if err != nil {
		//log.Print("Err unmarshalling asn1Data", asn1Data, rest)
		return nil, err
	}
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	return parseCertificate(&certificate{
		Raw:            tbsCert.Raw,
		TBSCertificate: tbsCert})
}

var (
	oidExtensionSubjectKeyId                   = []int{2, 5, 29, 14}
	oidExtensionKeyUsage                       = []int{2, 5, 29, 15}
	oidExtensionExtendedKeyUsage               = []int{2, 5, 29, 37}
	oidExtensionAuthorityKeyId                 = []int{2, 5, 29, 35}
	oidExtensionBasicConstraints               = []int{2, 5, 29, 19}
	oidExtensionSubjectAltName                 = []int{2, 5, 29, 17}
	oidExtensionIssuerAltName                  = []int{2, 5, 29, 18}
	oidExtensionCertificatePolicies            = []int{2, 5, 29, 32}
	oidExtensionNameConstraints                = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints          = []int{2, 5, 29, 31}
	oidExtensionAuthorityInfoAccess            = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionSignedCertificateTimestampList = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

// NOTE ignoring authorityKeyID argument
func buildExtensions(template *Certificate, _ []byte) (ret []pkix.Extension, err error) {
	ret = make([]pkix.Extension, 10 /* Max number of elements. */)
	n := 0

	if template.KeyUsage != 0 &&
		!oidInExtensions(oidExtensionKeyUsage, template.ExtraExtensions) {
		ret[n].Id = oidExtensionKeyUsage
		ret[n].Critical = true

		var a [2]byte
		a[0] = reverseBitsInAByte(byte(template.KeyUsage))
		a[1] = reverseBitsInAByte(byte(template.KeyUsage >> 8))

		l := 1
		if a[1] != 0 {
			l = 2
		}

		ret[n].Value, err = asn1.Marshal(asn1.BitString{Bytes: a[0:l], BitLength: l * 8})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.ExtKeyUsage) > 0 || len(template.UnknownExtKeyUsage) > 0) &&
		!oidInExtensions(oidExtensionExtendedKeyUsage, template.ExtraExtensions) {
		ret[n].Id = oidExtensionExtendedKeyUsage

		var oids []asn1.ObjectIdentifier
		for _, u := range template.ExtKeyUsage {
			if oid, ok := oidFromExtKeyUsage(u); ok {
				oids = append(oids, oid)
			} else {
				panic("internal error")
			}
		}

		oids = append(oids, template.UnknownExtKeyUsage...)

		ret[n].Value, err = asn1.Marshal(oids)
		if err != nil {
			return
		}
		n++
	}

	if template.BasicConstraintsValid && !oidInExtensions(oidExtensionBasicConstraints, template.ExtraExtensions) {
		// Leaving MaxPathLen as zero indicates that no Max path
		// length is desired, unless MaxPathLenZero is set. A value of
		// -1 causes encoding/asn1 to omit the value as desired.
		maxPathLen := template.MaxPathLen
		if maxPathLen == 0 && !template.MaxPathLenZero {
			maxPathLen = -1
		}
		ret[n].Id = oidExtensionBasicConstraints
		ret[n].Value, err = asn1.Marshal(basicConstraints{template.IsCA, maxPathLen})
		ret[n].Critical = true
		if err != nil {
			return
		}
		n++
	}

	if len(template.SubjectKeyId) > 0 && !oidInExtensions(oidExtensionSubjectKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectKeyId
		ret[n].Value, err = asn1.Marshal(template.SubjectKeyId)
		if err != nil {
			return
		}
		n++
	}

	if len(template.AuthorityKeyId) > 0 && !oidInExtensions(oidExtensionAuthorityKeyId, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityKeyId
		ret[n].Value, err = asn1.Marshal(authKeyId{template.AuthorityKeyId})
		if err != nil {
			return
		}
		n++
	}

	if (len(template.OCSPServer) > 0 || len(template.IssuingCertificateURL) > 0) &&
		!oidInExtensions(oidExtensionAuthorityInfoAccess, template.ExtraExtensions) {
		ret[n].Id = oidExtensionAuthorityInfoAccess
		var aiaValues []authorityInfoAccess
		for _, name := range template.OCSPServer {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessOcsp,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		for _, name := range template.IssuingCertificateURL {
			aiaValues = append(aiaValues, authorityInfoAccess{
				Method:   oidAuthorityInfoAccessIssuers,
				Location: asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)},
			})
		}
		ret[n].Value, err = asn1.Marshal(aiaValues)
		if err != nil {
			return
		}
		n++
	}

	if (len(template.DNSNames) > 0 || len(template.EmailAddresses) > 0 || len(template.IPAddresses) > 0) &&
		!oidInExtensions(oidExtensionSubjectAltName, template.ExtraExtensions) {
		ret[n].Id = oidExtensionSubjectAltName
		ret[n].Value, err = marshalSANs(template.DNSNames, template.EmailAddresses, template.IPAddresses)
		if err != nil {
			return
		}
		n++
	}

	if len(template.PolicyIdentifiers) > 0 &&
		!oidInExtensions(oidExtensionCertificatePolicies, template.ExtraExtensions) {
		ret[n].Id = oidExtensionCertificatePolicies
		policies := make([]policyInformation, len(template.PolicyIdentifiers))
		for i, policy := range template.PolicyIdentifiers {
			policies[i].Policy = policy
		}
		ret[n].Value, err = asn1.Marshal(policies)
		if err != nil {
			return
		}
		n++
	}

	// TODO: this can be cleaned up in go1.10
	if (len(template.PermittedEmailAddresses) > 0 || len(template.PermittedDNSNames) > 0 || len(template.PermittedDirectoryNames) > 0 ||
		len(template.PermittedIPAddresses) > 0 || len(template.ExcludedEmailAddresses) > 0 || len(template.ExcludedDNSNames) > 0 ||
		len(template.ExcludedDirectoryNames) > 0 || len(template.ExcludedIPAddresses) > 0) &&
		!oidInExtensions(oidExtensionNameConstraints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionNameConstraints
		if template.NameConstraintsCritical {
			ret[n].Critical = true
		}

		var out nameConstraints

		for _, permitted := range template.PermittedEmailAddresses {
			out.Permitted = append(out.Permitted, generalSubtree{Value: asn1.RawValue{Tag: 1, Class: 2, Bytes: []byte(permitted.Data)}})
		}
		for _, excluded := range template.ExcludedEmailAddresses {
			out.Excluded = append(out.Excluded, generalSubtree{Value: asn1.RawValue{Tag: 1, Class: 2, Bytes: []byte(excluded.Data)}})
		}
		for _, permitted := range template.PermittedDNSNames {
			out.Permitted = append(out.Permitted, generalSubtree{Value: asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(permitted.Data)}})
		}
		for _, excluded := range template.ExcludedDNSNames {
			out.Excluded = append(out.Excluded, generalSubtree{Value: asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(excluded.Data)}})
		}
		for _, permitted := range template.PermittedDirectoryNames {
			var dn []byte
			dn, err = asn1.Marshal(permitted.Data.ToRDNSequence())
			if err != nil {
				return
			}
			out.Permitted = append(out.Permitted, generalSubtree{Value: asn1.RawValue{Tag: 4, Class: 2, IsCompound: true, Bytes: dn}})
		}
		for _, excluded := range template.ExcludedDirectoryNames {
			var dn []byte
			dn, err = asn1.Marshal(excluded.Data.ToRDNSequence())
			if err != nil {
				return
			}
			out.Excluded = append(out.Excluded, generalSubtree{Value: asn1.RawValue{Tag: 4, Class: 2, IsCompound: true, Bytes: dn}})
		}
		for _, permitted := range template.PermittedIPAddresses {
			ip := append(permitted.Data.IP, permitted.Data.Mask...)
			out.Permitted = append(out.Permitted, generalSubtree{Value: asn1.RawValue{Tag: 7, Class: 2, Bytes: ip}})
		}
		for _, excluded := range template.ExcludedIPAddresses {
			ip := append(excluded.Data.IP, excluded.Data.Mask...)
			out.Excluded = append(out.Excluded, generalSubtree{Value: asn1.RawValue{Tag: 7, Class: 2, Bytes: ip}})
		}
		ret[n].Value, err = asn1.Marshal(out)
		if err != nil {
			return
		}
		n++
	}

	if len(template.CRLDistributionPoints) > 0 &&
		!oidInExtensions(oidExtensionCRLDistributionPoints, template.ExtraExtensions) {
		ret[n].Id = oidExtensionCRLDistributionPoints

		var crlDp []distributionPoint
		for _, name := range template.CRLDistributionPoints {
			rawFullName, _ := asn1.Marshal(asn1.RawValue{Tag: 6, Class: 2, Bytes: []byte(name)})

			dp := distributionPoint{
				DistributionPoint: distributionPointName{
					FullName: asn1.RawValue{Tag: 0, Class: 2, IsCompound: true, Bytes: rawFullName},
				},
			}
			crlDp = append(crlDp, dp)
		}

		ret[n].Value, err = asn1.Marshal(crlDp)
		if err != nil {
			return
		}
		n++
	}

	// Adding another extension here? Remember to update the Max number
	// of elements in the make() at the top of the function.

	return append(ret[:n], template.ExtraExtensions...), nil
}

// GetParsedDNSNames returns a list of parsed SAN DNS names. It is used to cache the parsing result and
// speed up zlint linters. If invalidateCache is true, then the cache is repopulated with current list of string from
// Certificate.DNSNames. This parameter should always be false, unless the Certificate.DNSNames have been modified
// after calling GetParsedDNSNames the previous time.
func (c *Certificate) GetParsedDNSNames(invalidateCache bool) []ParsedDomainName {
	if c.parsedDNSNames != nil && !invalidateCache {
		return c.parsedDNSNames
	}
	c.parsedDNSNames = make([]ParsedDomainName, len(c.DNSNames))

	for i := range c.DNSNames {
		var parsedDomain, parseError = publicsuffix.ParseFromListWithOptions(publicsuffix.DefaultList,
			c.DNSNames[i],
			&publicsuffix.FindOptions{IgnorePrivate: true, DefaultRule: publicsuffix.DefaultRule})

		c.parsedDNSNames[i].DomainString = c.DNSNames[i]
		c.parsedDNSNames[i].ParsedDomain = parsedDomain
		c.parsedDNSNames[i].ParseError = parseError
	}

	return c.parsedDNSNames
}

// GetParsedCommonName returns parsed subject CommonName. It is used to cache the parsing result and
// speed up zlint linters. If invalidateCache is true, then the cache is repopulated with current subject CommonName.
// This parameter should always be false, unless the Certificate.Subject.CommonName have been modified
// after calling GetParsedSubjectCommonName the previous time.
func (c *Certificate) GetParsedSubjectCommonName(invalidateCache bool) ParsedDomainName {
	if c.parsedCommonName != nil && !invalidateCache {
		return *c.parsedCommonName
	}

	var parsedDomain, parseError = publicsuffix.ParseFromListWithOptions(publicsuffix.DefaultList,
		c.Subject.CommonName,
		&publicsuffix.FindOptions{IgnorePrivate: true, DefaultRule: publicsuffix.DefaultRule})

	c.parsedCommonName = &ParsedDomainName{
		DomainString: c.Subject.CommonName,
		ParsedDomain: parsedDomain,
		ParseError:   parseError,
	}

	return *c.parsedCommonName
}

// CheckSignature reports whether the signature on c is valid.
func (c *CertificateRequest) CheckSignature() error {
	return CheckSignatureFromKey(c.PublicKey, c.SignatureAlgorithm, c.RawTBSCertificateRequest, c.Signature)
}
