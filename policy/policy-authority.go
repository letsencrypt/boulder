// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"math/rand"
	"net"
	"regexp"
	"strings"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/net/publicsuffix"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// PolicyAuthorityImpl enforces CA policy decisions.
type PolicyAuthorityImpl struct {
	log *blog.AuditLogger
	DB  *PolicyAuthorityDatabaseImpl

	EnforceWhitelist  bool
	enabledChallenges map[string]bool
	pseudoRNG         *rand.Rand
}

// NewPolicyAuthorityImpl constructs a Policy Authority.
func NewPolicyAuthorityImpl(dbMap *gorp.DbMap, enforceWhitelist bool, challengeTypes map[string]bool) (*PolicyAuthorityImpl, error) {
	logger := blog.GetAuditLogger()
	logger.Notice("Policy Authority Starting")

	// Setup policy db
	padb, err := NewPolicyAuthorityDatabaseImpl(dbMap)
	if err != nil {
		return nil, err
	}

	pa := PolicyAuthorityImpl{
		log:               logger,
		DB:                padb,
		EnforceWhitelist:  enforceWhitelist,
		enabledChallenges: challengeTypes,
		// We don't need real randomness for this.
		pseudoRNG: rand.New(rand.NewSource(99)),
	}

	return &pa, nil
}

const (
	maxLabels = 10

	// DNS defines max label length as 63 characters. Some implementations allow
	// more, but we will be conservative.
	maxLabelLength = 63

	// This is based off maxLabels * maxLabelLength, but is also a restriction based
	// on the max size of indexed storage in the issuedNames table.
	maxDNSIdentifierLength = 640

	// whitelistedPartnerRegID is the registartion ID we check for to see if we need
	// to skip the domain whitelist (but not the blacklist). This is for an
	// early partner integration during the beta period and should be removed
	// later.
	whitelistedPartnerRegID = 131
)

var dnsLabelRegexp = regexp.MustCompile("^[a-z0-9][a-z0-9-]{0,62}$")
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

var (
	errInvalidIdentifier   = core.MalformedRequestError("Invalid identifier type")
	errNonPublic           = core.MalformedRequestError("Name does not end in a public suffix")
	errICANNTLD            = core.MalformedRequestError("Name is an ICANN TLD")
	errBlacklisted         = core.MalformedRequestError("Name is blacklisted")
	errNotWhitelisted      = core.MalformedRequestError("Name is not whitelisted")
	errInvalidDNSCharacter = core.MalformedRequestError("Invalid character in DNS name")
	errNameTooLong         = core.MalformedRequestError("DNS name too long")
	errIPAddress           = core.MalformedRequestError("Issuance for IP addresses not supported")
	errTooManyLabels       = core.MalformedRequestError("DNS name has too many labels")
	errEmptyName           = core.MalformedRequestError("DNS name was empty")
	errTooFewLabels        = core.MalformedRequestError("DNS name does not have enough labels")
	errLabelTooShort       = core.MalformedRequestError("DNS label is too short")
	errLabelTooLong        = core.MalformedRequestError("DNS label is too long")
	errIDNNotSupported     = core.MalformedRequestError("Internationalized domain names (starting with xn--) not yet supported")
)

// WillingToIssue determines whether the CA is willing to issue for the provided
// identifier. It expects domains in id to be lowercase to prevent mismatched
// cases breaking queries.
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
// If WillingToIssue returns an error, it will be of type MalformedRequestError.
func (pa PolicyAuthorityImpl) WillingToIssue(id core.AcmeIdentifier, regID int64) error {
	if id.Type != core.IdentifierDNS {
		return errInvalidIdentifier
	}
	domain := id.Value

	if domain == "" {
		return errEmptyName
	}

	for _, ch := range []byte(domain) {
		if !isDNSCharacter(ch) {
			return errInvalidDNSCharacter
		}
	}

	if len(domain) > 255 {
		return errNameTooLong
	}

	if ip := net.ParseIP(domain); ip != nil {
		return errIPAddress
	}

	labels := strings.Split(domain, ".")
	if len(labels) > maxLabels {
		return errTooManyLabels
	}
	if len(labels) < 2 {
		return errTooFewLabels
	}
	for _, label := range labels {
		if len(label) < 1 {
			return errLabelTooShort
		}
		if len(label) > maxLabelLength {
			return errLabelTooLong
		}

		if !dnsLabelRegexp.MatchString(label) {
			return errInvalidDNSCharacter
		}

		if label[len(label)-1] == '-' {
			return errInvalidDNSCharacter
		}

		if punycodeRegexp.MatchString(label) {
			return errIDNNotSupported
		}
	}

	// Names must end in an ICANN TLD, but they must not be equal to an ICANN TLD.
	icannTLD, err := publicsuffix.ICANNTLD(domain)
	if err != nil {
		return errNonPublic
	}
	if icannTLD == domain {
		return errICANNTLD
	}

	// Use the domain whitelist if the PA has been asked to. However, if the
	// registration ID is from a whitelisted partner we're allowing to register
	// any domain, they can get in, too.
	enforceWhitelist := pa.EnforceWhitelist
	if regID == whitelistedPartnerRegID {
		enforceWhitelist = false
	}

	// Require no match against blacklist and if enforceWhitelist is true
	// require domain to match a whitelist rule.
	if err := pa.DB.CheckHostLists(domain, enforceWhitelist); err != nil {
		return err
	}

	return nil
}

// ChallengesFor makes a decision of what challenges, and combinations, are
// acceptable for the given identifier.
//
// Note: Current implementation is static, but future versions may not be.
func (pa PolicyAuthorityImpl) ChallengesFor(identifier core.AcmeIdentifier, accountKey *jose.JsonWebKey) ([]core.Challenge, [][]int, error) {
	challenges := []core.Challenge{}

	if pa.enabledChallenges[core.ChallengeTypeHTTP01] {
		challenges = append(challenges, core.HTTPChallenge01(accountKey))
	}

	if pa.enabledChallenges[core.ChallengeTypeTLSSNI01] {
		challenges = append(challenges, core.TLSSNIChallenge01(accountKey))
	}

	if pa.enabledChallenges[core.ChallengeTypeDNS01] {
		challenges = append(challenges, core.DNSChallenge01(accountKey))
	}

	// We shuffle the challenges and combinations to prevent ACME clients from
	// relying on the specific order that boulder returns them in.
	shuffled := make([]core.Challenge, len(challenges))
	combinations := make([][]int, len(challenges))

	for i, challIdx := range pa.pseudoRNG.Perm(len(challenges)) {
		shuffled[i] = challenges[challIdx]
		combinations[i] = []int{i}
	}

	shuffledCombos := make([][]int, len(combinations))
	for i, comboIdx := range pa.pseudoRNG.Perm(len(combinations)) {
		shuffledCombos[i] = combinations[comboIdx]
	}

	return shuffled, shuffledCombos, nil
}
