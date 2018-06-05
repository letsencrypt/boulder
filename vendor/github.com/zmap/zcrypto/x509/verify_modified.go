// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"net"
	"time"
)

const (
	// NotAuthorizedToSign results when a certificate is signed by another
	// which isn't marked as a CA certificate.
	NotAuthorizedToSign InvalidReason = iota

	// Expired results when a certificate has expired, based on the time
	// given in the VerifyOptions.
	Expired

	// CANotAuthorizedForThisName results when an intermediate or root
	// certificate has a name constraint which doesn't include the name
	// being checked.
	CANotAuthorizedForThisName

	// CANotAuthorizedForThisEmail results when an intermediate or root
	// certificate has a name constraint which doesn't include the email
	// being checked.
	CANotAuthorizedForThisEmail

	// CANotAuthorizedForThisIP results when an intermediate or root
	// certificate has a name constraint which doesn't include the IP
	// being checked.
	CANotAuthorizedForThisIP

	// CANotAuthorizedForThisDirectory results when an intermediate or root
	// certificate has a name constraint which doesn't include the directory
	// being checked.
	CANotAuthorizedForThisDirectory

	// TooManyIntermediates results when a path length constraint is
	// violated.
	TooManyIntermediates

	// IncompatibleUsage results when the certificate's key usage indicates
	// that it may only be used for a different purpose.
	IncompatibleUsage

	// NameMismatch results when the subject name of a parent certificate
	// does not match the issuer name in the child.
	NameMismatch

	// NeverValid results when the certificate could never have been valid due to
	// some date-related issue, e.g. NotBefore > NotAfter.
	NeverValid

	// IsSelfSigned results when the certificate is self-signed and not a trusted
	// root.
	IsSelfSigned
)

func (e CertificateInvalidError) Error() string {
	switch e.Reason {
	case NotAuthorizedToSign:
		return "x509: certificate is not authorized to sign other certificates"
	case Expired:
		return "x509: certificate has expired or is not yet valid"
	case CANotAuthorizedForThisName:
		return "x509: a root or intermediate certificate is not authorized to sign in this domain"
	case CANotAuthorizedForThisEmail:
		return "x509: a root or intermediate certificate is not authorized to sign this email address"
	case CANotAuthorizedForThisIP:
		return "x509: a root or intermediate certificate is not authorized to sign this IP address"
	case CANotAuthorizedForThisDirectory:
		return "x509: a root or intermediate certificate is not authorized to sign in this directory"
	case TooManyIntermediates:
		return "x509: too many intermediates for path length constraint"
	case IncompatibleUsage:
		return "x509: certificate specifies an incompatible key usage"
	case NameMismatch:
		return "x509: issuer name does not match subject from issuing certificate"
	case NeverValid:
		return "x509: certificate will never be valid"
	}
	return "x509: unknown error"
}

const maxIntermediateCount = 10

// VerifyOptions contains parameters for Certificate.Verify. It's a structure
// because other PKIX verification APIs have ended up needing many options.
type VerifyOptions struct {
	DNSName      string
	EmailAddress string
	IPAddress    net.IP

	Intermediates *CertPool
	Roots         *CertPool // if nil, the system roots are used
	CurrentTime   time.Time // if zero, the current time is used
	// KeyUsage specifies which Extended Key Usage values are acceptable.
	// An empty list means ExtKeyUsageServerAuth. Key usage is considered a
	// constraint down the chain which mirrors Windows CryptoAPI behaviour,
	// but not the spec. To accept any key usage, include ExtKeyUsageAny.
	KeyUsages []ExtKeyUsage
}

// NOTE: the stdlib function does many more checks and is preferable. For backwards compatibility using this version

// isValid performs validity checks on the c. It will never return a
// date-related error.
func (c *Certificate) isValid(certType CertificateType, currentChain CertificateChain) error {

	// KeyUsage status flags are ignored. From Engineering Security, Peter
	// Gutmann: A European government CA marked its signing certificates as
	// being valid for encryption only, but no-one noticed. Another
	// European CA marked its signature keys as not being valid for
	// signatures. A different CA marked its own trusted root certificate
	// as being invalid for certificate signing.  Another national CA
	// distributed a certificate to be used to encrypt data for the
	// country’s tax authority that was marked as only being usable for
	// digital signatures but not for encryption. Yet another CA reversed
	// the order of the bit flags in the keyUsage due to confusion over
	// encoding endianness, essentially setting a random keyUsage in
	// certificates that it issued. Another CA created a self-invalidating
	// certificate by adding a certificate policy statement stipulating
	// that the certificate had to be used strictly as specified in the
	// keyUsage, and a keyUsage containing a flag indicating that the RSA
	// encryption key could only be used for Diffie-Hellman key agreement.

	if certType == CertificateTypeIntermediate && (!c.BasicConstraintsValid || !c.IsCA) {
		return CertificateInvalidError{c, NotAuthorizedToSign}
	}

	if c.BasicConstraintsValid && c.MaxPathLen >= 0 {
		numIntermediates := len(currentChain) - 1
		if numIntermediates > c.MaxPathLen {
			return CertificateInvalidError{c, TooManyIntermediates}
		}
	}

	if len(currentChain) > maxIntermediateCount {
		return CertificateInvalidError{c, TooManyIntermediates}
	}

	return nil
}

// Verify attempts to verify c by building one or more chains from c to a
// certificate in opts.Roots, using certificates in opts.Intermediates if
// needed. If successful, it returns one or more chains where the first
// element of the chain is c and the last element is from opts.Roots.
//
// If opts.Roots is nil and system roots are unavailable the returned error
// will be of type SystemRootsError.
//
// WARNING: this doesn't do any revocation checking.
func (c *Certificate) Verify(opts VerifyOptions) (current, expired, never []CertificateChain, err error) {

	if opts.Roots == nil {
		opts.Roots = systemRootsPool()
		if opts.Roots == nil {
			err = SystemRootsError{}
			return
		}
	}

	err = c.isValid(CertificateTypeLeaf, nil)
	if err != nil {
		return
	}

	candidateChains, err := c.buildChains(make(map[int][]CertificateChain), []*Certificate{c}, &opts)
	if err != nil {
		return
	}

	keyUsages := opts.KeyUsages
	if len(keyUsages) == 0 {
		keyUsages = []ExtKeyUsage{ExtKeyUsageServerAuth}
	}

	// If any key usage is acceptable then we're done.
	hasKeyUsageAny := false
	for _, usage := range keyUsages {
		if usage == ExtKeyUsageAny {
			hasKeyUsageAny = true
			break
		}
	}

	var chains []CertificateChain
	if hasKeyUsageAny {
		chains = candidateChains
	} else {
		for _, candidate := range candidateChains {
			if checkChainForKeyUsage(candidate, keyUsages) {
				chains = append(chains, candidate)
			}
		}
	}

	if len(chains) == 0 {
		err = CertificateInvalidError{c, IncompatibleUsage}
		return
	}

	current, expired, never = FilterByDate(chains, opts.CurrentTime)
	if len(current) == 0 {
		if len(expired) > 0 {
			err = CertificateInvalidError{c, Expired}
		} else if len(never) > 0 {
			err = CertificateInvalidError{c, NeverValid}
		}
		return
	}

	if len(opts.DNSName) > 0 {
		err = c.VerifyHostname(opts.DNSName)
		if err != nil {
			return
		}
	}
	return
}

//// Verify attempts to verify c by building one or more chains from c to a
//// certificate in opts.Roots, using certificates in opts.Intermediates if
//// needed. If successful, it returns one or more chains where the first
//// element of the chain is c and the last element is from opts.Roots.
////
//// If opts.Roots is nil and system roots are unavailable the returned error
//// will be of type SystemRootsError.
////
//// WARNING: this doesn't do any revocation checking.
//func (c *Certificate) Verify(opts VerifyOptions) (current, expired, never []CertificateChain, err error) {
//	// Platform-specific verification needs the ASN.1 contents so
//	// this makes the behavior consistent across platforms.
//	if len(c.Raw) == 0 {
//		err = errNotParsed
//		return
//	}
//	if opts.Intermediates != nil {
//		for _, intermediate := range opts.Intermediates.certs {
//			if len(intermediate.Raw) == 0 {
//				err = errNotParsed
//				return
//			}
//		}
//	}
//
//	//// Use Windows's own verification and chain building.
//	//if opts.Roots == nil && runtime.GOOS == "windows" {
//	//	return c.systemVerify(&opts)
//	//}
//
//	if opts.Roots == nil {
//		opts.Roots = systemRootsPool()
//		if opts.Roots == nil {
//			err = SystemRootsError{}
//			return
//		}
//	}
//
//	err = c.isValid(leafCertificate, nil, &opts)
//	if err != nil {
//		return
//	}
//
//	candidateChains, err := c.buildChains(make(map[int][]CertificateChain), []*Certificate{c}, &opts)
//	if err != nil {
//		return
//	}
//
//	if len(opts.DNSName) > 0 {
//		err = c.VerifyHostname(opts.DNSName)
//		if err != nil {
//			return
//		}
//	}
//
//	keyUsages := opts.KeyUsages
//	if len(keyUsages) == 0 {
//		keyUsages = []ExtKeyUsage{ExtKeyUsageServerAuth}
//	}
//
//	var hasKeyUsageAny bool
//	// If any key usage is acceptable then we're done.
//	for _, usage := range keyUsages {
//		if usage == ExtKeyUsageAny {
//			hasKeyUsageAny = true
//			break
//		}
//	}
//
//	var chains []CertificateChain
//	if hasKeyUsageAny {
//		chains = candidateChains
//	} else {
//		for _, candidate := range candidateChains {
//			if checkChainForKeyUsage(candidate, keyUsages) {
//				chains = append(chains, candidate)
//			}
//		}
//	}
//
//	if len(chains) == 0 {
//		err = CertificateInvalidError{c, IncompatibleUsage}
//		return
//	}
//
//	current, expired, never = FilterByDate(chains, opts.CurrentTime)
//	if len(current) == 0 {
//		if len(expired) > 0 {
//			err = CertificateInvalidError{c, Expired}
//		} else if len(never) > 0 {
//			err = CertificateInvalidError{c, NeverValid}
//		}
//		return
//	}
//
//	return
//}

// buildChains returns all chains of length < maxIntermediateCount. Chains begin
// the certificate being validated (chain[0] = c), and end at a root. It
// enforces that all intermediates can sign certificates, and checks signatures.
// It does not enforce expiration.
func (c *Certificate) buildChains(cache map[int][]CertificateChain, currentChain CertificateChain, opts *VerifyOptions) (chains []CertificateChain, err error) {

	// If the certificate being validated is a root, add the chain of length one
	// containing just the root. Only do this on the first call to buildChains,
	// when the len(currentChain) = 1.
	if len(currentChain) == 1 && opts.Roots.Contains(c) {
		chains = append(chains, CertificateChain{c})
	}

	if len(chains) == 0 && c.SelfSigned {
		err = CertificateInvalidError{c, IsSelfSigned}
	}

	// Find roots that signed c and have matching SKID/AKID and Subject/Issuer.
	possibleRoots, failedRoot, rootErr := opts.Roots.findVerifiedParents(c)

	// If any roots are parents of c, create new chain for each one of them.
	for _, rootNum := range possibleRoots {
		root := opts.Roots.certs[rootNum]
		err = root.isValid(CertificateTypeRoot, currentChain)
		if err != nil {
			continue
		}
		if !currentChain.CertificateInChain(root) {
			chains = append(chains, currentChain.AppendToFreshChain(root))
		}
	}

	// The root chains of length N+1 are now "done". Now we'll look for any
	// intermediates that issue this certificate, meaning that any chain to a root
	// through these intermediates is at least length N+2.
	possibleIntermediates, failedIntermediate, intermediateErr := opts.Intermediates.findVerifiedParents(c)

	for _, intermediateNum := range possibleIntermediates {
		intermediate := opts.Intermediates.certs[intermediateNum]
		if opts.Roots.Contains(intermediate) {
			continue
		}
		if currentChain.CertificateSubjectAndKeyInChain(intermediate) {
			continue
		}
		err = intermediate.isValid(CertificateTypeIntermediate, currentChain)
		if err != nil {
			continue
		}

		// We don't want to add any certificate to chains that doesn't somehow get
		// to a root. We don't know if all chains through the intermediates will end
		// at a root, so we slice off the back half of the chain and try to build
		// that part separately.
		childChains, ok := cache[intermediateNum]
		if !ok {
			childChains, err = intermediate.buildChains(cache, currentChain.AppendToFreshChain(intermediate), opts)
			cache[intermediateNum] = childChains
		}
		chains = append(chains, childChains...)
	}

	if len(chains) > 0 {
		err = nil
	}

	if len(chains) == 0 && err == nil {
		hintErr := rootErr
		hintCert := failedRoot
		if hintErr == nil {
			hintErr = intermediateErr
			hintCert = failedIntermediate
		}
		err = UnknownAuthorityError{c, hintErr, hintCert}
	}

	return
}

// earlier returns the earlier of a and b
func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// later returns the later of a and b
func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// check expirations divides chains into a set of disjoint chains, containing
// current chains valid now, expired chains that were valid at some point, and
// the set of chains that were never valid.
func FilterByDate(chains []CertificateChain, now time.Time) (current, expired, never []CertificateChain) {
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		leaf := chain[0]
		lowerBound := leaf.NotBefore
		upperBound := leaf.NotAfter
		for _, c := range chain[1:] {
			lowerBound = later(lowerBound, c.NotBefore)
			upperBound = earlier(upperBound, c.NotAfter)
		}
		valid := lowerBound.Before(now) && upperBound.After(now)
		wasValid := lowerBound.Before(upperBound)
		if valid && !wasValid {
			// Math/logic tells us this is impossible.
			panic("valid && !wasValid should not be possible")
		}
		if valid {
			current = append(current, chain)
		} else if wasValid {
			expired = append(expired, chain)
		} else {
			never = append(never, chain)
		}
	}
	return
}
