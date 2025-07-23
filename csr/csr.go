package csr

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"net/netip"
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
	invalidURIPresent   = berrors.BadCSRError("CSR contains one or more URI fields")
	invalidNoIdent      = berrors.BadCSRError("at least one identifier is required")
	invalidIPCN         = berrors.BadCSRError("CSR contains IP address in Common Name")
)

// VerifyCSR checks the validity of a x509.CertificateRequest. It uses
// identifier.FromCSR to normalize the DNS names before checking whether we'll
// issue for them.
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
	if len(csr.URIs) > 0 {
		return invalidURIPresent
	}

	// Reject all CSRs which have an IP address in the CN. We want to get rid of
	// CNs entirely anyway, and IP addresses are a new feature, so don't let
	// clients get in the habit of including them in the CN. We don't use
	// CNFromCSR here because that also filters out IP address CNs, for defense
	// in depth.
	_, err = netip.ParseAddr(csr.Subject.CommonName)
	if err == nil { // Inverted! Successful parsing is a bad thing in this case.
		return invalidIPCN
	}

	// FromCSR also performs normalization, returning values that may not match
	// the literal CSR contents.
	idents := identifier.FromCSR(csr)
	if len(idents) == 0 {
		return invalidNoIdent
	}
	if len(idents) > maxNames {
		return berrors.BadCSRError("CSR contains more than %d identifiers", maxNames)
	}

	err = pa.WillingToIssue(idents)
	if err != nil {
		return err
	}
	return nil
}

// CNFromCSR returns the lower-cased Subject Common Name from the CSR, if a
// short enough CN was provided. If it was too long or appears to be an IP,
// there will be no CN. If none was provided, the CN will be the first SAN that
// is short enough, which is done only for backwards compatibility with prior
// Let's Encrypt behaviour.
func CNFromCSR(csr *x509.CertificateRequest) string {
	if len(csr.Subject.CommonName) > maxCNLength {
		return ""
	}

	if csr.Subject.CommonName != "" {
		_, err := netip.ParseAddr(csr.Subject.CommonName)
		if err == nil { // Inverted! Successful parsing is a bad thing in this case.
			return ""
		}

		return strings.ToLower(csr.Subject.CommonName)
	}

	// If there's no CN already, but we want to set one, promote the first dnsName
	// SAN which is shorter than the maximum acceptable CN length (if any). We
	// will never promote an ipAddress SAN to the CN.
	for _, name := range csr.DNSNames {
		if len(name) <= maxCNLength {
			return strings.ToLower(name)
		}
	}

	return ""
}
