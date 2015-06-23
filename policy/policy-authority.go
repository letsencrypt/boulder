// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"fmt"
	"crypto/x509"
	"crypto/rsa"
	"net"
	"regexp"
	"strings"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/sa"

	gorp "github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
	blog "github.com/letsencrypt/boulder/log"
	jose "github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/square/go-jose"
)

// The Policy Authority has a separate, read-only DB that contains information
// about existing certificates issued by other CAs, used to restrict issuance
// for the names in those certificates.
// The Policy Authority code is embedded in both the RA and the CA, and so
// its config is in the Common struct.
type Config struct {
	Driver string
	Name   string
}

// PolicyAuthorityImpl enforces CA policy decisions.
type PolicyAuthorityImpl struct {
	log *blog.AuditLogger
	padb PADB

	PublicSuffixList map[string]bool // A copy of the DNS root zone
	Blacklist        map[string]bool // A blacklist of denied names
}

type PADB interface {
	externalCertDataForFQDN(fqdn string) ([]core.ExternalCert, error)
}
type PADBImpl struct {
	dbMap *gorp.DbMap
}

func (padb PADBImpl) externalCertDataForFQDN(fqdn string) ([]core.ExternalCert, error) {
	return []core.ExternalCert{}, nil
}

// NewPolicyAuthorityImpl constructs a Policy Authority.
func NewPolicyAuthorityImpl(config Config) (*PolicyAuthorityImpl, error) {
	logger := blog.GetAuditLogger()
	logger.Notice("Policy Authority Starting")

	pa := PolicyAuthorityImpl{log: logger}

	dbMap, err := sa.NewDbMap(config.Driver, config.Name)
	if err != nil {
		return nil, err
	}

	dbMap.AddTableWithName(core.IdentifierData{}, "identifierData")
	dbMap.AddTableWithName(core.ExternalCert{}, "externalCerts")
	pa.padb = PADBImpl{
		dbMap: dbMap,
	}

	// TODO: Add configurability
	pa.PublicSuffixList = PublicSuffixList
	pa.Blacklist = blacklist

	return &pa, nil
}

const maxLabels = 10

var dnsLabelRegexp = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$")
var punycodeRegexp = regexp.MustCompile("^xn--")

func isDNSCharacter(ch byte) bool {
	return ('a' <= ch && ch <= 'z') ||
		('A' <= ch && ch <= 'Z') ||
		('0' <= ch && ch <= '9') ||
		ch == '.' || ch == '-'
}

// Test whether the domain name indicated by the label set is a label-wise
// suffix match for the provided suffix set.  If the `properSuffix` flag is
// set, then the name is required to not be in the suffix set (i.e., it must
// have at least one label beyond any suffix in the set).
func suffixMatch(labels []string, suffixSet map[string]bool, properSuffix bool) bool {
	for i := range labels {
		if domain := strings.Join(labels[i:], "."); suffixSet[domain] {
			// If we match on the whole domain, gate on properSuffix
			return !properSuffix || (i > 0)
		}
	}
	return false
}

// InvalidIdentifierError indicates that we didn't understand the IdentifierType
// provided.
type InvalidIdentifierError struct{}

// SyntaxError indicates that the user input was not well formatted.
type SyntaxError struct{}

// NonPublicError indicates that one or more identifiers were not on the public
// Internet.
type NonPublicError struct{}

// BlacklistedError indicates we have blacklisted one or more of these identifiers.
type BlacklistedError struct{}

func (e InvalidIdentifierError) Error() string { return "Invalid identifier type" }
func (e SyntaxError) Error() string            { return "Syntax error" }
func (e NonPublicError) Error() string         { return "Name does not end in a public suffix" }
func (e BlacklistedError) Error() string       { return "Name is blacklisted" }

// WillingToIssue determines whether the CA is willing to issue for the provided
// identifier.
//
// We place several criteria on identifiers we are willing to issue for:
//
//  * MUST self-identify as DNS identifiers
//  * MUST contain only bytes in the DNS hostname character set
//  * MUST NOT have more than maxLabels labels
//  * MUST follow the DNS hostname syntax rules in RFC 1035 and RFC 2181
//    In particular:
//    * MUST NOT contain underscores
//  * MUST NOT contain IDN labels (xn--)
//  * MUST NOT match the syntax of an IP address
//  * MUST end in a public suffix
//  * MUST have at least one label in addition to the public suffix
//  * MUST NOT be a label-wise suffix match for a name on the black list,
//    where comparison is case-independent (normalized to lower case)
//
// XXX: Is there any need for this method to be constant-time?  We're
//      going to refuse to issue anyway, but timing could leak whether
//      names are on the blacklist.
//
// XXX: We should probably fold everything to lower-case somehow.
func (pa PolicyAuthorityImpl) WillingToIssue(id core.AcmeIdentifier) error {
	if id.Type != core.IdentifierDNS {
		return InvalidIdentifierError{}
	}
	domain := id.Value

	for _, ch := range []byte(domain) {
		if !isDNSCharacter(ch) {
			return SyntaxError{}
		}
	}

	domain = strings.ToLower(domain)
	if len(domain) > 255 {
		return SyntaxError{}
	}

	if ip := net.ParseIP(domain); ip != nil {
		return SyntaxError{}
	}

	labels := strings.Split(domain, ".")
	if len(labels) > maxLabels || len(labels) < 2 {
		return SyntaxError{}
	}
	for _, label := range labels {
		// DNS defines max label length as 63 characters. Some implementations allow
		// more, but we will be conservative.
		if len(label) < 1 || len(label) > 63 {
			return SyntaxError{}
		}

		if !dnsLabelRegexp.MatchString(label) {
			return SyntaxError{}
		}

		if punycodeRegexp.MatchString(label) {
			return SyntaxError{}
		}
	}

	// Require match to PSL, plus at least one label
	if !suffixMatch(labels, pa.PublicSuffixList, true) {
		return NonPublicError{}
	}

	// Require no match against blacklist
	if suffixMatch(labels, pa.Blacklist, false) {
		return BlacklistedError{}
	}

	return nil
}

// ChallengesFor makes a decision of what challenges, and combinations, are
// acceptable for the given identifier.
//
// Note: Current implementation is static, but future versions may not be.
// TODO: When parsing SPKI, check for key type.
func (pa PolicyAuthorityImpl) ChallengesFor(identifier core.AcmeIdentifier) (challenges []core.Challenge, combinations [][]int) {
	if identifier.Type != core.IdentifierDNS {
		// TODO: Add error return type
		pa.log.Debug("Invalid identifier type")
		return nil, nil
	}
	challenges = []core.Challenge{
		core.SimpleHTTPChallenge(),
		core.DvsniChallenge(),
		core.DNSChallenge(),
	}
	combinations = [][]int{
		[]int{0},
		[]int{1},
		[]int{2},
	}
	certs, err := pa.padb.externalCertDataForFQDN(identifier.Value)
	if err != nil {
		pa.log.Debug("Failure looking up external certs")
		return nil, nil
	}
	if len(certs) == 0 {
		pa.log.Debug(fmt.Sprintf("No external certs for %s", identifier.Value))
		return challenges, combinations
	}

	var hints core.POPChallengeHints
	// TODO: Double-check sanity of input data because it originally came from the Internet
	// TODO: Maintain sets of each data type and de-duplicate them.
	for _, cert := range certs {
		hints.CertFingerprints = append(hints.CertFingerprints, cert.SHA1)
		hints.Issuers = append(hints.Issuers, cert.Issuer)
		pubKey, err := x509.ParsePKIXPublicKey(cert.SPKI)
		if err != nil {
			pa.log.Debug(fmt.Sprintf("Failure parsing pubkey: %s", err))
			return nil, nil
		}
		switch pk := pubKey.(type) {
			case *rsa.PublicKey:
				hints.JWKs = append(hints.JWKs, jose.JsonWebKey{
					Key: pk,
					// TODO: core.ProofOfPosessionChallenge should check the algorithms on
					// JWKs and propagate up to the Alg field on the challenge. Alternately,
					// remove the Alg field from the challenge and depend on the JWKs.
					Algorithm: "RS256",
				})
			default:
				// If any of the returned certs has a non-RSA key, return error.
				pa.log.Debug("ExternalCerts provided a cert with non-RSA key")
				return nil, nil
		}
	}

	// Create the proofOfPosession challenge, add it to the list of challenges,
	// and add its index to each of the existing combinations (so proofOfPosession
	// is required in combination with a DV challenge).
	popChallenge := core.ProofOfPosessionChallenge(hints)
	popChallengeIndex := len(challenges)
	challenges = append(challenges, popChallenge)
	for _, combo := range combinations {
		combo = append(combo, popChallengeIndex)
	}

	return challenges, combinations
}
