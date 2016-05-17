package csr

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/letsencrypt/boulder/core"
)

// VerifyCSR checks the validity of a x509.CertificateRequest
func VerifyCSR(csr *x509.CertificateRequest, maxNames int, keyPolicy *core.KeyPolicy, pa core.PolicyAuthority, regID int64) error {
	key, ok := csr.PublicKey.(crypto.PublicKey)
	if !ok {
		return errors.New("invalid public key in CSR")
	}
	if err := keyPolicy.GoodKey(key); err != nil {
		return fmt.Errorf("invalid public key in CSR: %s", err)
	}
	if core.BadSignatureAlgorithms[csr.SignatureAlgorithm] {
		// go1.6 provides a stringer for x509.SignatureAlgorithm but 1.5.x
		// does not
		return errors.New("signature algorithm not supported")
	}
	if err := csr.CheckSignature(); err != nil {
		return errors.New("invalid signature on CSR")
	}
	if len(csr.DNSNames) == 0 && csr.Subject.CommonName == "" {
		return errors.New("at least one DNS name is required")
	}
	if len(csr.Subject.CommonName) > core.MaxCNLength {
		return fmt.Errorf("CN was longer than %d bytes", core.MaxCNLength)
	}
	if maxNames > 0 && len(csr.DNSNames) > maxNames {
		return fmt.Errorf("CSR contains more than %d DNS names", maxNames)
	}
	badNames := []string{}
	for _, name := range csr.DNSNames {
		if err := pa.WillingToIssue(core.AcmeIdentifier{
			Type:  core.IdentifierDNS,
			Value: name,
		}, regID); err != nil {
			badNames = append(badNames, name)
		}
	}
	if len(badNames) > 0 {
		return fmt.Errorf("policy forbids issuing for: %s", strings.Join(badNames, ", "))
	}
	return nil
}

// NormalizeCSR deduplicates and lowers the case ofdNSNames and lowers the case of the subject CN. If forceCNFromSAN is true it will
// also hoist a dNSName into the CN if the latter is empty
func NormalizeCSR(csr *x509.CertificateRequest, forceCNFromSAN bool) {
	if forceCNFromSAN && csr.Subject.CommonName == "" {
		if len(csr.DNSNames) > 0 {
			csr.Subject.CommonName = csr.DNSNames[0]
		}
	} else if csr.Subject.CommonName != "" {
		csr.DNSNames = append(csr.DNSNames, csr.Subject.CommonName)
	}
	csr.Subject.CommonName = strings.ToLower(csr.Subject.CommonName)
	csr.DNSNames = core.UniqueLowerNames(csr.DNSNames)
}
