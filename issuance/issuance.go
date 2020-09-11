package issuance

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
	"github.com/letsencrypt/boulder/cmd"
	"github.com/letsencrypt/boulder/lint"
	"github.com/letsencrypt/boulder/policyasn1"
	zlint "github.com/zmap/zlint/v2/lint"
)

// IssuanceRequest describes a certificate issuance request
type IssuanceRequest struct {
	PublicKey crypto.PublicKey

	Serial []byte

	NotBefore time.Time
	NotAfter  time.Time

	CommonName string
	DNSNames   []string

	IncludeMustStaple bool
	IncludeCTPoison   bool
	SCTList           []ct.SignedCertificateTimestamp
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
	UseForRSALeaves   bool
	UseForECDSALeaves bool

	AllowMustStaple bool
	AllowCTPoison   bool
	AllowSCTList    bool
	AllowCommonName bool

	IssuerURL           string
	OCSPURL             string
	CRLURL              string
	Policies            []PolicyInformation
	MaxValidityPeriod   cmd.ConfigDuration
	MaxValidityBackdate cmd.ConfigDuration
}

// The internal structure created by reading in ProfileConfigs
type issuanceProfile struct {
	useForRSALeaves   bool
	useForECDSALeaves bool

	allowMustStaple bool
	allowCTPoison   bool
	allowSCTList    bool
	allowCommonName bool

	sigAlg    x509.SignatureAlgorithm
	ocspURL   string
	crlURL    string
	issuerURL string
	policies  *pkix.Extension

	maxBackdate time.Duration
	maxValidity time.Duration
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

var stringToQualifierType = map[string]asn1.ObjectIdentifier{
	"id-qt-cps": policyasn1.CPSQualifierOID,
}

func newProfile(config ProfileConfig) (*issuanceProfile, error) {
	if config.IssuerURL == "" {
		return nil, errors.New("Issuer URL is required")
	}
	if config.OCSPURL == "" {
		return nil, errors.New("OCSP URL is required")
	}
	sp := &issuanceProfile{
		useForRSALeaves:   config.UseForRSALeaves,
		useForECDSALeaves: config.UseForECDSALeaves,
		allowMustStaple:   config.AllowMustStaple,
		allowCTPoison:     config.AllowCTPoison,
		allowSCTList:      config.AllowSCTList,
		allowCommonName:   config.AllowCommonName,
		issuerURL:         config.IssuerURL,
		crlURL:            config.CRLURL,
		ocspURL:           config.OCSPURL,
		maxBackdate:       config.MaxValidityBackdate.Duration,
		maxValidity:       config.MaxValidityPeriod.Duration,
	}
	if len(config.Policies) > 0 {
		var policies []policyasn1.PolicyInformation
		for _, policyConfig := range config.Policies {
			id, err := parseOID(policyConfig.OID)
			if err != nil {
				return nil, fmt.Errorf("failed parsing policy OID %q: %s", policyConfig.OID, err)
			}
			pi := policyasn1.PolicyInformation{Policy: id}
			for _, qualifierConfig := range policyConfig.Qualifiers {
				qt, ok := stringToQualifierType[qualifierConfig.Type]
				if !ok {
					return nil, fmt.Errorf("unknown qualifier type: %s", qualifierConfig.Type)
				}
				pq := policyasn1.PolicyQualifier{
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

// requestValid verifies the passed IssuanceRequest against the profile. If the
// request doesn't match the signing profile an error is returned.
func (p *issuanceProfile) requestValid(clk clock.Clock, req *IssuanceRequest) error {
	switch req.PublicKey.(type) {
	case *rsa.PublicKey:
		if !p.useForRSALeaves {
			return errors.New("cannot sign RSA public keys")
		}
	case *ecdsa.PublicKey:
		if !p.useForECDSALeaves {
			return errors.New("cannot sign ECDSA public keys")
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

	if !p.allowCommonName && req.CommonName != "" {
		return errors.New("common name cannot be included")
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

	if len(req.Serial) > 20 || len(req.Serial) < 8 {
		return errors.New("serial must be between 8 and 20 bytes")
	}

	return nil
}

var defaultEKU = []x509.ExtKeyUsage{
	x509.ExtKeyUsageServerAuth,
	x509.ExtKeyUsageClientAuth,
}

func (p *issuanceProfile) generateTemplate(clk clock.Clock) *x509.Certificate {
	template := &x509.Certificate{
		SignatureAlgorithm:    p.sigAlg,
		ExtKeyUsage:           defaultEKU,
		OCSPServer:            []string{p.ocspURL},
		IssuingCertificateURL: []string{p.issuerURL},
		BasicConstraintsValid: true,
	}

	if p.crlURL != "" {
		template.CRLDistributionPoints = []string{p.crlURL}
	}

	if p.policies != nil {
		template.ExtraExtensions = []pkix.Extension{*p.policies}
	}

	return template
}

// Issuer is capable of issuing new certificates
type Issuer struct {
	cert    *x509.Certificate
	signer  crypto.Signer
	profile *issuanceProfile
	lintKey crypto.Signer
	lints   zlint.Registry
	clk     clock.Clock
}

// IssuerConfig contains the information necessary to construct an Issuer
type IssuerConfig struct {
	Cert         *x509.Certificate
	Signer       crypto.Signer
	Profile      ProfileConfig
	IgnoredLints []string
	Clk          clock.Clock
}

// New constructs an Issuer from the provided IssuerConfig
func New(config IssuerConfig) (*Issuer, error) {
	profile, err := newProfile(config.Profile)
	if err != nil {
		return nil, err
	}
	switch k := config.Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		profile.sigAlg = x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			profile.sigAlg = x509.ECDSAWithSHA256
		case elliptic.P384():
			profile.sigAlg = x509.ECDSAWithSHA384
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
	default:
		return nil, errors.New("unsupported issuer key type")
	}
	lintKey, err := lint.MakeSigner(config.Signer)
	if err != nil {
		return nil, err
	}
	lints, err := zlint.GlobalRegistry().Filter(zlint.FilterOptions{
		ExcludeNames: config.IgnoredLints,
		ExcludeSources: []zlint.LintSource{
			// We ignore the ETSI and EVG lints since they do not
			// apply to the certificates we issue, and not attempting
			// to apply them will save some cycles.
			zlint.CABFEVGuidelines,
			zlint.EtsiEsi,
		},
	})
	if err != nil {
		return nil, err
	}
	i := &Issuer{
		cert:    config.Cert,
		signer:  config.Signer,
		clk:     config.Clk,
		lints:   lints,
		lintKey: lintKey,
		profile: profile,
	}
	return i, nil
}

var ctPoisonExt = pkix.Extension{
	// OID for CT poison, RFC 6962 (was never assigned a proper id-pe- name)
	Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
	Value:    asn1.NullBytes,
	Critical: true,
}

// OID for SCT list, RFC 6962 (was never assigned a proper id-pe- name)
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
	// RFC 7633: id-pe-tlsfeature OBJECT IDENTIFIER ::=  { id-pe 24 }
	Id: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24},
	// ASN.1 encoding of:
	// SEQUENCE
	//   INTEGER 5
	// where "5" is the status_request feature (RFC 6066)
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
// signs it. Before signing the certificate with the issuer's private
// key, it is signed using a throwaway key so that it can be linted using
// zlint. If the linting fails, an error is returned and the certificate
// is not signed using the issuer's key.
func (i *Issuer) Issue(req *IssuanceRequest) ([]byte, error) {
	// check request is valid according to the issuance profile
	if err := i.profile.requestValid(i.clk, req); err != nil {
		return nil, err
	}

	// generate template from the issuance profile
	template := i.profile.generateTemplate(i.clk)

	// populate template from the issuance request
	template.NotBefore, template.NotAfter = req.NotBefore, req.NotAfter
	template.SerialNumber = big.NewInt(0).SetBytes(req.Serial)
	if req.CommonName != "" {
		template.Subject.CommonName = req.CommonName
	}
	template.DNSNames = req.DNSNames
	template.AuthorityKeyId = i.cert.SubjectKeyId
	skid, err := generateSKID(req.PublicKey)
	if err != nil {
		return nil, err
	}
	template.SubjectKeyId = skid
	switch req.PublicKey.(type) {
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
	lintCert, err := lint.MakeLintCert(template, i.cert, req.PublicKey, i.lintKey)
	if err != nil {
		return nil, err
	}
	err = lint.LintCert(lintCert, i.lints)
	if err != nil {
		return nil, fmt.Errorf("tbsCertificate linting failed: %w", err)
	}

	return x509.CreateCertificate(rand.Reader, template, i.cert, req.PublicKey, i.signer)
}

func ContainsMustStaple(extensions []pkix.Extension) bool {
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
// the provided precertificate. It returns an error if the precertificate doesn't
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
		CommonName:        precert.Subject.CommonName,
		DNSNames:          precert.DNSNames,
		IncludeMustStaple: ContainsMustStaple(precert.Extensions),
		SCTList:           scts,
	}, nil
}
