package csr

import (
	"crypto"
	"errors"
	"fmt"
	"strings"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/goodkey"
	oldx509 "github.com/letsencrypt/go/src/crypto/x509"
)

// maxCNLength is the maximum length allowed for the common name as specified in RFC 5280
const maxCNLength = 64

// This map is used to detect algorithms in crypto/x509 that
// are no longer considered sufficiently strong.
// * No MD2, MD5, or SHA-1
// * No DSA
//
// SHA1WithRSA is allowed because there's still a fair bit of it
// out there, but we should try to remove it soon.
var badSignatureAlgorithms = map[oldx509.SignatureAlgorithm]bool{
	oldx509.UnknownSignatureAlgorithm: true,
	oldx509.MD2WithRSA:                true,
	oldx509.MD5WithRSA:                true,
	oldx509.DSAWithSHA1:               true,
	oldx509.DSAWithSHA256:             true,
	oldx509.ECDSAWithSHA1:             true,
}

// VerifyCSR checks the validity of a x509.CertificateRequest. Before doing checks it normalizes
// the CSR which lowers the case of DNS names and subject CN, and if forceCNFromSAN is true it
// will hoist a DNS name into the CN if it is empty.
func VerifyCSR(csr *oldx509.CertificateRequest, maxNames int, keyPolicy *goodkey.KeyPolicy, pa core.PolicyAuthority, forceCNFromSAN bool, regID int64) error {
	normalizeCSR(csr, forceCNFromSAN)
	key, ok := csr.PublicKey.(crypto.PublicKey)
	if !ok {
		return errors.New("invalid public key in CSR")
	}
	if err := keyPolicy.GoodKey(key); err != nil {
		return fmt.Errorf("invalid public key in CSR: %s", err)
	}
	if badSignatureAlgorithms[csr.SignatureAlgorithm] {
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
	if len(csr.Subject.CommonName) > maxCNLength {
		return fmt.Errorf("CN was longer than %d bytes", maxCNLength)
	}
	if maxNames > 0 && len(csr.DNSNames) > maxNames {
		return fmt.Errorf("CSR contains more than %d DNS names", maxNames)
	}
	badNames := []string{}
	for _, name := range csr.DNSNames {
		if err := pa.WillingToIssue(core.AcmeIdentifier{
			Type:  core.IdentifierDNS,
			Value: name,
		}); err != nil {
			badNames = append(badNames, name)
		}
	}
	if len(badNames) > 0 {
		return fmt.Errorf("policy forbids issuing for: %s", strings.Join(badNames, ", "))
	}
	return nil
}

// normalizeCSR deduplicates and lowers the case of dNSNames and the subject CN.
// If forceCNFromSAN is true it will also hoist a dNSName into the CN if it is empty.
func normalizeCSR(csr *oldx509.CertificateRequest, forceCNFromSAN bool) {
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
