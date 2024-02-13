package issuance

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/zmap/zlint/v3/lint"

	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/linter"
)

type CRLProfileConfig struct {
	ValidityInterval config.Duration
	MaxBackdate      config.Duration
}

type CRLProfile struct {
	validityInterval time.Duration
	maxBackdate      time.Duration

	lints lint.Registry
}

func NewCRLProfile(config CRLProfileConfig) (*CRLProfile, error) {
	lifetime := config.ValidityInterval.Duration
	if lifetime >= 10*24*time.Hour {
		return nil, fmt.Errorf("crl lifetime cannot be more than 10 days, got %q", lifetime)
	} else if lifetime <= 0*time.Hour {
		return nil, fmt.Errorf("crl lifetime must be positive, got %q", lifetime)
	}

	if config.MaxBackdate.Duration < 0 {
		return nil, fmt.Errorf("crl max backdate must be non-negative, got %q", config.MaxBackdate)
	}

	reg, err := linter.NewRegistry(nil)
	if err != nil {
		return nil, fmt.Errorf("creating lint registry: %w", err)
	}

	return &CRLProfile{
		validityInterval: config.ValidityInterval.Duration,
		maxBackdate:      config.MaxBackdate.Duration,
		lints:            reg,
	}, nil
}

type CRLRequest struct {
	Number *big.Int
	Shard  int64

	ThisUpdate time.Time

	Entries []x509.RevocationListEntry

	// TODO(#7296): Remove this and instead compute it from Issuer.CRLBaseURL
	DeprecatedIDPBaseURL string
}

func (i *Issuer) IssueCRL(prof *CRLProfile, req *CRLRequest) ([]byte, error) {
	backdatedBy := i.clk.Now().Sub(req.ThisUpdate)
	if backdatedBy > prof.maxBackdate {
		return nil, fmt.Errorf("ThisUpdate is too far in the past (%s>%s)", backdatedBy, prof.maxBackdate)
	}
	if backdatedBy < 0 {
		return nil, fmt.Errorf("ThisUpdate is in the future (%s>%s)", req.ThisUpdate, i.clk.Now())
	}

	template := &x509.RevocationList{
		RevokedCertificateEntries: req.Entries,
		Number:                    req.Number,
		ThisUpdate:                req.ThisUpdate,
		NextUpdate:                req.ThisUpdate.Add(-time.Second).Add(prof.validityInterval),
	}

	if i.crlURLBase == "" && req.DeprecatedIDPBaseURL == "" {
		return nil, fmt.Errorf("CRL must contain an issuingDistributionPoint")
	}

	var idps []string
	if i.crlURLBase != "" {
		idps = append(idps, fmt.Sprintf("%s/%d.crl", i.crlURLBase, req.Shard))
	}
	if req.DeprecatedIDPBaseURL != "" {
		// TODO(#7296): Remove this fallback once CCADB and all non-expired certs
		// contain the new-style CRLDP URL instead.
		idps = append(idps, fmt.Sprintf("%s/%d/%d.crl", req.DeprecatedIDPBaseURL, i.NameID(), req.Shard))
	}
	idp, err := makeIDPExt(idps)
	if err != nil {
		return nil, fmt.Errorf("creating IDP extension: %w", err)
	}
	template.ExtraExtensions = append(template.ExtraExtensions, idp)

	err = i.Linter.CheckCRL(template, prof.lints)
	if err != nil {
		return nil, err
	}

	crlBytes, err := x509.CreateRevocationList(
		rand.Reader,
		template,
		i.Cert.Certificate,
		i.Signer,
	)
	if err != nil {
		return nil, err
	}

	return crlBytes, nil
}

// distributionPointName represents the ASN.1 DistributionPointName CHOICE as
// defined in RFC 5280 Section 4.2.1.13. We only use one of the fields, so the
// others are omitted.
type distributionPointName struct {
	// Technically, FullName is of type GeneralNames, which is of type SEQUENCE OF
	// GeneralName. But GeneralName itself is of type CHOICE, and the ans1.Marhsal
	// function doesn't support marshalling structs to CHOICEs, so we have to use
	// asn1.RawValue and encode the GeneralName ourselves.
	FullName []asn1.RawValue `asn1:"optional,tag:0"`
}

// issuingDistributionPoint represents the ASN.1 IssuingDistributionPoint
// SEQUENCE as defined in RFC 5280 Section 5.2.5. We only use two of the fields,
// so the others are omitted.
type issuingDistributionPoint struct {
	DistributionPoint     distributionPointName `asn1:"optional,tag:0"`
	OnlyContainsUserCerts bool                  `asn1:"optional,tag:1"`
}

// makeIDPExt returns a critical IssuingDistributionPoint extension containing
// the given URLs and with the OnlyContainsUserCerts boolean set to true.
func makeIDPExt(urls []string) (pkix.Extension, error) {
	var gns []asn1.RawValue
	for _, url := range urls {
		gns = append(gns, asn1.RawValue{ // GeneralName
			Class: 2, // context-specific
			Tag:   6, // uniformResourceIdentifier, IA5String
			Bytes: []byte(url),
		})
	}

	val := issuingDistributionPoint{
		DistributionPoint:     distributionPointName{FullName: gns},
		OnlyContainsUserCerts: true,
	}

	valBytes, err := asn1.Marshal(val)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 28}, // id-ce-issuingDistributionPoint
		Value:    valBytes,
		Critical: true,
	}, nil
}
