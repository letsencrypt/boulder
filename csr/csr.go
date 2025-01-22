package csr

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"strings"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/goodkey"
	"github.com/letsencrypt/boulder/identifier"
)

// maxCNLength is the maximum length allowed for the common name as specified in RFC 5280
const maxCNLength = 64

// This map is used to decide which CSR signing algorithms we consider
// strong enough to use. Significantly the missing algorithms are:
// * No algorithms using MD2, MD5, or SHA-1
// * No DSA algorithms
var goodSignatureAlgorithms = map[x509.SignatureAlgorithm]bool{
	x509.SHA256WithRSA:   true,
	x509.SHA384WithRSA:   true,
	x509.SHA512WithRSA:   true,
	x509.ECDSAWithSHA256: true,
	x509.ECDSAWithSHA384: true,
	x509.ECDSAWithSHA512: true,
}

var (
	invalidPubKey       = berrors.BadCSRError("invalid public key in CSR")
	unsupportedSigAlg   = berrors.BadCSRError("signature algorithm not supported")
	invalidSig          = berrors.BadCSRError("invalid signature on CSR")
	invalidEmailPresent = berrors.BadCSRError("CSR contains one or more email address fields")
	invalidIPPresent    = berrors.BadCSRError("CSR contains one or more IP address fields")
	invalidNoDNS        = berrors.BadCSRError("at least one DNS name is required")
)

// VerifyCSR checks the validity of a x509.CertificateRequest. It uses
// NamesFromCSR to normalize the DNS names before checking whether we'll issue
// for them.
func VerifyCSR(ctx context.Context, csr *x509.CertificateRequest, maxNames int, keyPolicy *goodkey.KeyPolicy, pa core.PolicyAuthority) error {
	key, ok := csr.PublicKey.(crypto.PublicKey)
	if !ok {
		return invalidPubKey
	}
	err := keyPolicy.GoodKey(ctx, key)
	if err != nil {
		if errors.Is(err, goodkey.ErrBadKey) {
			return berrors.BadCSRError("invalid public key in CSR: %s", err)
		}
		return berrors.InternalServerError("error checking key validity: %s", err)
	}
	if !goodSignatureAlgorithms[csr.SignatureAlgorithm] {
		return unsupportedSigAlg
	}

	err = csr.CheckSignature()
	if err != nil {
		return invalidSig
	}
	if len(csr.EmailAddresses) > 0 {
		return invalidEmailPresent
	}
	if len(csr.IPAddresses) > 0 {
		return invalidIPPresent
	}

	// NamesFromCSR also performs normalization, returning values that may not
	// match the literal CSR contents.
	names := NamesFromCSR(csr)

	if len(names.SANs) == 0 && names.CN == "" {
		return invalidNoDNS
	}
	if len(names.CN) > maxCNLength {
		return berrors.BadCSRError("CN was longer than %d bytes", maxCNLength)
	}
	if len(names.SANs) > maxNames {
		return berrors.BadCSRError("CSR contains more than %d DNS names", maxNames)
	}

	err = pa.WillingToIssue(identifier.SliceNewDNS(names.SANs))
	if err != nil {
		return err
	}
	return nil
}

type names struct {
	SANs []string
	CN   string
}

// NamesFromCSR deduplicates and lower-cases the Subject Common Name and Subject
// Alternative Names from the CSR. If a CN was provided, it will be used if it
// is short enough, otherwise there will be no CN. If no CN was provided, the CN
// will be the first SAN that is short enough, which is done only for backwards
// compatibility with prior Let's Encrypt behaviour. The resulting SANs will
// always include the original CN, if any.
func NamesFromCSR(csr *x509.CertificateRequest) names {
	// Produce a new "sans" slice with the same memory address as csr.DNSNames
	// but force a new allocation if an append happens so that we don't
	// accidentally mutate the underlying csr.DNSNames array.
	sans := csr.DNSNames[0:len(csr.DNSNames):len(csr.DNSNames)]

	if csr.Subject.CommonName != "" {
		sans = append(sans, csr.Subject.CommonName)
	}

	if len(csr.Subject.CommonName) > maxCNLength {
		return names{SANs: core.UniqueLowerNames(sans)}
	}

	if csr.Subject.CommonName != "" {
		return names{SANs: core.UniqueLowerNames(sans), CN: strings.ToLower(csr.Subject.CommonName)}
	}

	// If there's no CN already, but we want to set one, promote the first SAN
	// which is shorter than the maximum acceptable CN length (if any).
	for _, name := range sans {
		if len(name) <= maxCNLength {
			return names{SANs: core.UniqueLowerNames(sans), CN: strings.ToLower(name)}
		}
	}

	return names{SANs: core.UniqueLowerNames(sans)}
}
