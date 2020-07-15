package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/jmhodges/clock"
	zlintx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v2"
	"github.com/zmap/zlint/v2/lint"
)

type IssuanceRequest struct {
	PublicKey crypto.PublicKey

	Serial []byte

	DNSNames []string

	IncludeMustStaple bool
	IncludeCTPoison   bool
	IncludeSCTList    []ct.SignedCertificateTimestamp
}

type policyInformation struct {
}

type signingProfile struct {
	allowRSAKeys   bool
	allowECDSAKeys bool

	allowMustStaple bool
	allowCTPoison   bool
	allowSCTList    bool

	// -----
	sigAlg         x509.SignatureAlgorithm
	keyUsage       x509.KeyUsage
	extKeyUsage    []x509.ExtKeyUsage
	ocspURL        string
	crlURL         string
	issuerURL      string
	policies       pkix.Extension
	validityPeriod time.Duration
	backdate       time.Duration
}

// requestValid verifies the passed IssuanceRequest agains the signingProfile. If the
// request doesn't match the signing profile an error is returned.
func (p *signingProfile) requestValid(req *IssuanceRequest) error {
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

	if !p.allowSCTList && len(req.IncludeSCTList) > 0 {
		return errors.New("sct list extension cannot be included")
	}

	if req.IncludeCTPoison && req.IncludeSCTList != nil {
		return errors.New("cannot include ct poison and sct list extensions")
	}

	return nil
}

func (p *signingProfile) generateTemplate(clk clock.Clock) *x509.Certificate {
	template := &x509.Certificate{
		SignatureAlgorithm: p.sigAlg,
		KeyUsage:           p.keyUsage,
		ExtKeyUsage:        p.extKeyUsage,
	}
	if p.ocspURL != "" {
		template.OCSPServer = []string{p.ocspURL}
	}
	if p.crlURL != "" {
		template.CRLDistributionPoints = []string{p.crlURL}
	}
	if p.issuerURL != "" {
		template.IssuingCertificateURL = []string{p.issuerURL}
	}

	template.NotBefore = clk.Now()
	if p.backdate != 0 {
		template.NotBefore.Add(-p.backdate)
	}
	template.NotAfter = template.NotBefore.Add(p.validityPeriod)

	template.Extensions = []pkix.Extension{p.policies}

	return template
}

type Signer struct {
	issuer  *x509.Certificate
	signer  crypto.Signer
	profile signingProfile
	clk     clock.Clock
	lintKey crypto.Signer
	lints   lint.Registry
}

func NewSigner() (*Signer, error) {
	return nil, nil
}

var ctPoisonExt = pkix.Extension{
	Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
	Value: asn1.NullBytes,
}

func generateSCTListExt(scts []ct.SignedCertificateTimestamp) (pkix.Extension, error) {
	list := ctx509.SignedCertificateTimestampList{}
	for _, sct := range scts {
		sctBytes, err := cttls.Marshal(sct)
		if err != nil {
			return pkix.Extension{}, err
		}
		list.SCTList = append(list.SCTList, ctx509.SerializedSCT{Val: sctBytes})
	}
	extBytes, err := cttls.Marshal(list)
	if err != nil {
		return pkix.Extension{}, nil
	}
	return pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
		Value: extBytes,
	}, nil
}

func (s Signer) Issue(req *IssuanceRequest) ([]byte, error) {
	// check request is valid according to the issuance profile
	if err := s.profile.requestValid(req); err != nil {
		return nil, err
	}

	// generate template from the issuance profile
	template := s.profile.generateTemplate(s.clk)

	// populate template from the issuance request
	template.PublicKey = req.PublicKey
	template.SerialNumber = big.NewInt(0).SetBytes(req.Serial)
	template.DNSNames = req.DNSNames

	if req.IncludeCTPoison {
		template.Extensions = append(template.Extensions, ctPoisonExt)
	} else if req.IncludeSCTList != nil {
		sctListExt, err := generateSCTListExt(req.IncludeSCTList)
		if err != nil {
			return nil, err
		}
		template.Extensions = append(template.Extensions, sctListExt)
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
		// should probably extract the errors at this point
		return nil, errors.New("bad! linting failed")
	}

	return x509.CreateCertificate(rand.Reader, template, s.issuer, req.PublicKey, s.signer)
}
