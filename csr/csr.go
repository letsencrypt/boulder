package csr

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/goodkey"
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
var badSignatureAlgorithms = map[x509.SignatureAlgorithm]bool{
	x509.UnknownSignatureAlgorithm: true,
	x509.MD2WithRSA:                true,
	x509.MD5WithRSA:                true,
	x509.DSAWithSHA1:               true,
	x509.DSAWithSHA256:             true,
	x509.ECDSAWithSHA1:             true,
}

var (
	invalidPubKey       = berrors.MalformedError("invalid public key in CSR")
	unsupportedSigAlg   = berrors.MalformedError("signature algorithm not supported")
	invalidSig          = berrors.MalformedError("invalid signature on CSR")
	invalidEmailPresent = berrors.MalformedError("CSR contains one or more email address fields")
	invalidIPPresent    = berrors.MalformedError("CSR contains one or more IP address fields")
	invalidNoDNS        = berrors.MalformedError("at least one DNS name is required")
)

// VerifyCSR checks the validity of a x509.CertificateRequest. Before doing checks it normalizes
// the CSR which lowers the case of DNS names and subject CN, and if forceCNFromSAN is true it
// will hoist a DNS name into the CN if it is empty.
func VerifyCSR(csr *x509.CertificateRequest, maxNames int, keyPolicy *goodkey.KeyPolicy, pa core.PolicyAuthority, forceCNFromSAN bool, regID int64) error {
	normalizeCSR(csr, forceCNFromSAN)
	key, ok := csr.PublicKey.(crypto.PublicKey)
	if !ok {
		return invalidPubKey
	}
	if err := keyPolicy.GoodKey(key); err != nil {
		return berrors.MalformedError("invalid public key in CSR: %s", err)
	}
	if badSignatureAlgorithms[csr.SignatureAlgorithm] {
		// go1.6 provides a stringer for x509.SignatureAlgorithm but 1.5.x
		// does not
		return unsupportedSigAlg
	}
	if err := csr.CheckSignature(); err != nil {
		return invalidSig
	}
	if len(csr.EmailAddresses) > 0 {
		return invalidEmailPresent
	}
	if len(csr.IPAddresses) > 0 {
		return invalidIPPresent
	}
	if len(csr.DNSNames) == 0 && csr.Subject.CommonName == "" {
		return invalidNoDNS
	}
	if len(csr.Subject.CommonName) > maxCNLength {
		return berrors.MalformedError("CN was longer than %d bytes", maxCNLength)
	}
	if maxNames > 0 && len(csr.DNSNames) > maxNames {
		return berrors.MalformedError("CSR contains more than %d DNS names", maxNames)
	}
	badNames := []string{}
	for _, name := range csr.DNSNames {
		if err := pa.WillingToIssue(core.AcmeIdentifier{
			Type:  core.IdentifierDNS,
			Value: name,
		}); err != nil {
			badNames = append(badNames, fmt.Sprintf("%q", name))
		}
	}
	if len(badNames) > 0 {
		return berrors.MalformedError("policy forbids issuing for: %s", strings.Join(badNames, ", "))
	}
	return nil
}

// normalizeCSR deduplicates and lowers the case of dNSNames and the subject CN.
// If forceCNFromSAN is true it will also hoist a dNSName into the CN if it is empty.
func normalizeCSR(csr *x509.CertificateRequest, forceCNFromSAN bool) {
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
