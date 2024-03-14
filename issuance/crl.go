package issuance

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/zmap/zlint/v3/lint"

	"github.com/letsencrypt/boulder/config"
	"github.com/letsencrypt/boulder/crl/idp"
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
	idp, err := idp.MakeUserCertsExt(idps)
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
