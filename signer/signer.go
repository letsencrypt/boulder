package signer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/jmhodges/clock"
	zlintx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v2"
	"github.com/zmap/zlint/v2/lint"
)

// IssuanceRequest describes a certificate issuance request
type IssuanceRequest struct {
	PublicKey crypto.PublicKey

	Serial []byte

	NotBefore time.Time
	NotAfter  time.Time

	DNSNames []string

	IncludeMustStaple bool
	IncludeCTPoison   bool
	SCTList           []ct.SignedCertificateTimestamp
}

type signingProfile struct {
	allowRSAKeys   bool
	allowECDSAKeys bool

	allowMustStaple bool
	allowCTPoison   bool
	allowSCTList    bool

	sigAlg    x509.SignatureAlgorithm
	ocspURL   string
	crlURL    string
	issuerURL string
	policies  *pkix.Extension

	maxBackdate time.Duration
	maxValidity time.Duration
}

// PolicyQualifier describes a policy qualifier
type PolicyQualifier struct {
	Type  string
	Value string
}

// PolicyInformation describes a policy
type PolicyInformation struct {
	OID        string
	Qualifiers []PolicyQualifier
}

// ProfileConfig describes the certificate issuance constraints
type ProfileConfig struct {
	AllowRSAKeys    bool
	AllowECDSAKeys  bool
	AllowMustStaple bool
	AllowCTPoison   bool
	AllowSCTList    bool

	IssuerURL           string
	OCSPURL             string
	CRLURL              string
	Policies            []PolicyInformation
	MaxValidityPeriod   time.Duration
	MaxValidityBackdate time.Duration
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

type policyQualifier struct {
	OID   asn1.ObjectIdentifier
	Value string `asn1:"optional,ia5"`
}

type policyInformation struct {
	Policy     asn1.ObjectIdentifier
	Qualifiers []policyQualifier `asn1:"optional"`
}

var stringToQualifierType = map[string]asn1.ObjectIdentifier{
	"id-qt-cps": {1, 3, 6, 1, 5, 5, 7, 2, 1},
}

func newProfile(config ProfileConfig) (*signingProfile, error) {
	sp := &signingProfile{
		allowRSAKeys:    config.AllowRSAKeys,
		allowECDSAKeys:  config.AllowECDSAKeys,
		allowMustStaple: config.AllowMustStaple,
		allowCTPoison:   config.AllowCTPoison,
		allowSCTList:    config.AllowSCTList,
		issuerURL:       config.IssuerURL,
		crlURL:          config.CRLURL,
		ocspURL:         config.OCSPURL,
		maxBackdate:     config.MaxValidityBackdate,
		maxValidity:     config.MaxValidityPeriod,
	}
	if config.IssuerURL == "" {
		return nil, errors.New("Issuer URL is required")
	}
	if config.OCSPURL == "" {
		return nil, errors.New("OCSP URL is required")
	}
	if len(config.Policies) > 0 {
		var policies []policyInformation
		for _, policyConfig := range config.Policies {
			id, err := parseOID(policyConfig.OID)
			if err != nil {
				return nil, fmt.Errorf("failed parsing policy OID %q: %s", policyConfig.OID, err)
			}
			pi := policyInformation{Policy: id}
			for _, qualifierConfig := range policyConfig.Qualifiers {
				qt, ok := stringToQualifierType[qualifierConfig.Type]
				if !ok {
					return nil, fmt.Errorf("unknown qualifier type: %s", qualifierConfig.Type)
				}
				pq := policyQualifier{
					OID:   qt,
					Value: qualifierConfig.Value,
				}
				pi.Qualifiers = append(pi.Qualifiers, pq)
			}
			policies = append(policies, pi)
		}
		policyExtBytes, err := asn1.Marshal(policies)
		if err != nil {
			return nil, err
		}
		sp.policies = &pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 32},
			Value: policyExtBytes,
		}
	}
	return sp, nil
}

// requestValid verifies the passed IssuanceRequest agains the signingProfile. If the
// request doesn't match the signing profile an error is returned.
func (p *signingProfile) requestValid(clk clock.Clock, req *IssuanceRequest) error {
	switch req.PublicKey.(type) {
	case *rsa.PublicKey:
		if !p.allowRSAKeys {
			return errors.New("RSA keys not allowed")
		}
	case *ecdsa.PublicKey:
		if !p.allowECDSAKeys {
			return errors.New("ECDSA keys not allowed")
		}
	default:
		return errors.New("unsupported public key type")
	}

	if !p.allowMustStaple && req.IncludeMustStaple {
		return errors.New("must-staple extension cannot be included")
	}

	if !p.allowCTPoison && req.IncludeCTPoison {
		return errors.New("ct poison extension cannot be included")
	}

	if !p.allowSCTList && req.SCTList != nil {
		return errors.New("sct list extension cannot be included")
	}

	if req.IncludeCTPoison && req.SCTList != nil {
		return errors.New("cannot include both ct poison and sct list extensions")
	}

	validity := req.NotAfter.Sub(req.NotBefore)
	if validity <= 0 {
		return errors.New("NotAfter must be after NotBefore")
	}
	if validity > p.maxValidity {
		return fmt.Errorf("validity period is more than the maximum allowed period (%s>%s)", validity, p.maxValidity)
	}
	backdatedBy := clk.Now().Sub(req.NotBefore)
	if backdatedBy > p.maxBackdate {
		return fmt.Errorf("NotBefore is backdated more than the maximum allowed period (%s>%s)", backdatedBy, p.maxBackdate)
	}
	if backdatedBy < 0 {
		return errors.New("NotBefore is in the future")
	}

	return nil
}

var defaultEKU = []x509.ExtKeyUsage{
	x509.ExtKeyUsageClientAuth,
	x509.ExtKeyUsageServerAuth,
}

func (p *signingProfile) generateTemplate(clk clock.Clock) *x509.Certificate {
	template := &x509.Certificate{
		SignatureAlgorithm:    p.sigAlg,
		ExtKeyUsage:           defaultEKU,
		OCSPServer:            []string{p.ocspURL},
		IssuingCertificateURL: []string{p.issuerURL},
	}

	if p.crlURL != "" {
		template.CRLDistributionPoints = []string{p.crlURL}
	}

	if p.policies != nil {
		template.ExtraExtensions = []pkix.Extension{*p.policies}
	}

	return template
}

// Signer is a certificate signer
type Signer struct {
	issuer  *x509.Certificate
	signer  crypto.Signer
	profile *signingProfile
	clk     clock.Clock
	lintKey crypto.Signer
	lints   lint.Registry
}

// Config contains the information necessary to construct a Signer
type Config struct {
	Issuer       *x509.Certificate
	Signer       crypto.Signer
	IgnoredLints []string
	Clk          clock.Clock
	Profile      ProfileConfig
}

// NewSigner constructs a Signer from the provided Config
func NewSigner(config *Config) (*Signer, error) {
	profile, err := newProfile(config.Profile)
	if err != nil {
		return nil, err
	}
	lints, err := lint.GlobalRegistry().Filter(lint.FilterOptions{
		ExcludeNames: config.IgnoredLints,
	})
	if err != nil {
		return nil, err
	}
	var lk crypto.Signer
	switch k := config.Issuer.PublicKey.(type) {
	case *rsa.PublicKey:
		lk, err = rsa.GenerateKey(rand.Reader, k.Size())
		if err != nil {
			return nil, err
		}
		profile.sigAlg = x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		lk, err = ecdsa.GenerateKey(k.Curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		switch k.Curve {
		case elliptic.P256():
			profile.sigAlg = x509.ECDSAWithSHA256
		case elliptic.P384():
			profile.sigAlg = x509.ECDSAWithSHA384
		case elliptic.P521():
			profile.sigAlg = x509.ECDSAWithSHA512
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
	default:
		return nil, errors.New("unsupported issuer key type")
	}
	s := &Signer{
		issuer:  config.Issuer,
		signer:  config.Signer,
		clk:     config.Clk,
		lints:   lints,
		lintKey: lk,
		profile: profile,
	}
	return s, nil
}

var ctPoisonExt = pkix.Extension{
	Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
	Value: asn1.NullBytes,
}

var sctListOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

func generateSCTListExt(scts []ct.SignedCertificateTimestamp) (pkix.Extension, error) {
	list := ctx509.SignedCertificateTimestampList{}
	for _, sct := range scts {
		sctBytes, err := cttls.Marshal(sct)
		if err != nil {
			return pkix.Extension{}, err
		}
		list.SCTList = append(list.SCTList, ctx509.SerializedSCT{Val: sctBytes})
	}
	listBytes, err := cttls.Marshal(list)
	if err != nil {
		return pkix.Extension{}, err
	}
	extBytes, err := asn1.Marshal(listBytes)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:    sctListOID,
		Value: extBytes,
	}, nil
}

var mustStapleExt = pkix.Extension{
	Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24},
	Value: []byte{0x30, 0x03, 0x02, 0x01, 0x05},
}

func generateSKID(pk crypto.PublicKey) ([]byte, error) {
	pkBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}
	var pkixPublicKey struct {
		Algo      pkix.AlgorithmIdentifier
		BitString asn1.BitString
	}
	if _, err := asn1.Unmarshal(pkBytes, &pkixPublicKey); err != nil {
		return nil, err
	}
	skid := sha1.Sum(pkixPublicKey.BitString.Bytes)
	return skid[:], nil
}

// Issue generates a certificate from the provided issuance request and
// signs it. Before the signing the certificate with the issuers private
// key it is signed using a throwaway key so that it can be linted using
// zlint. If the linting fails an error is returned and the certificate
// is not signed using the issuers key.
func (s *Signer) Issue(req *IssuanceRequest) ([]byte, error) {
	// check request is valid according to the issuance profile
	if err := s.profile.requestValid(s.clk, req); err != nil {
		return nil, err
	}

	// generate template from the issuance profile
	template := s.profile.generateTemplate(s.clk)

	// populate template from the issuance request
	template.PublicKey = req.PublicKey
	template.NotBefore, template.NotAfter = req.NotBefore, req.NotAfter
	template.SerialNumber = big.NewInt(0).SetBytes(req.Serial)
	template.DNSNames = req.DNSNames
	template.AuthorityKeyId = s.issuer.SubjectKeyId
	skid, err := generateSKID(req.PublicKey)
	if err != nil {
		return nil, err
	}
	template.SubjectKeyId = skid
	switch template.PublicKey.(type) {
	case *rsa.PublicKey:
		template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	case *ecdsa.PublicKey:
		template.KeyUsage = x509.KeyUsageDigitalSignature
	}

	if req.IncludeCTPoison {
		template.ExtraExtensions = append(template.ExtraExtensions, ctPoisonExt)
	} else if req.SCTList != nil {
		sctListExt, err := generateSCTListExt(req.SCTList)
		if err != nil {
			return nil, err
		}
		template.ExtraExtensions = append(template.ExtraExtensions, sctListExt)
	}

	if req.IncludeMustStaple {
		template.ExtraExtensions = append(template.ExtraExtensions, mustStapleExt)
	}

	// check that the tbsCertificate is properly formed by signing it
	// with a throwaway key and then linting it using zlint
	lintCertBytes, err := x509.CreateCertificate(rand.Reader, template, s.issuer, template.PublicKey, s.lintKey)
	if err != nil {
		return nil, err
	}
	lintCert, err := zlintx509.ParseCertificate(lintCertBytes)
	if err != nil {
		return nil, err
	}
	results := zlint.LintCertificateEx(lintCert, s.lints)
	if results.NoticesPresent || results.WarningsPresent || results.ErrorsPresent || results.FatalsPresent {
		var badLints []string
		for lintName, result := range results.Results {
			if result.Status > lint.Pass {
				badLints = append(badLints, lintName)
			}
		}
		return nil, fmt.Errorf("tbsCertificate linting failed: %s", strings.Join(badLints, ", "))
	}

	return x509.CreateCertificate(rand.Reader, template, s.issuer, req.PublicKey, s.signer)
}

func containsMustStaple(extensions []pkix.Extension) bool {
	for _, ext := range extensions {
		if ext.Id.Equal(mustStapleExt.Id) && bytes.Equal(ext.Value, mustStapleExt.Value) {
			return true
		}
	}
	return false
}

func containsCTPoison(extensions []pkix.Extension) bool {
	for _, ext := range extensions {
		if ext.Id.Equal(ctPoisonExt.Id) && bytes.Equal(ext.Value, asn1.NullBytes) {
			return true
		}
	}
	return false
}

// RequestFromPrecert constructs a final certificate IssuanceRequest matching
// he provided precertificate. It returns an error if the precertificate doesn't
// contain the CT poison extension.
func RequestFromPrecert(precert *x509.Certificate, scts []ct.SignedCertificateTimestamp) (*IssuanceRequest, error) {
	if !containsCTPoison(precert.Extensions) {
		return nil, errors.New("provided certificate doesn't contain the CT poison extension")
	}
	return &IssuanceRequest{
		PublicKey:         precert.PublicKey,
		Serial:            precert.SerialNumber.Bytes(),
		NotBefore:         precert.NotBefore,
		NotAfter:          precert.NotAfter,
		DNSNames:          precert.DNSNames,
		IncludeMustStaple: containsMustStaple(precert.Extensions),
		SCTList:           scts,
	}, nil
}
