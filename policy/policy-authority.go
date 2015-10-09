// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"errors"
	"net"
	"regexp"
	"strings"

	"github.com/letsencrypt/boulder/Godeps/_workspace/src/github.com/letsencrypt/go-jose"
	"github.com/letsencrypt/boulder/Godeps/_workspace/src/gopkg.in/gorp.v1"
	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

// PolicyAuthorityImpl enforces CA policy decisions.
type PolicyAuthorityImpl struct {
	log *blog.AuditLogger
	DB  *PolicyAuthorityDatabaseImpl

	EnforceWhitelist bool
	PublicSuffixList map[string]bool // A copy of the DNS root zone
}

// NewPolicyAuthorityImpl constructs a Policy Authority.
func NewPolicyAuthorityImpl(dbMap *gorp.DbMap, enforceWhitelist bool) (*PolicyAuthorityImpl, error) {
	logger := blog.GetAuditLogger()
	logger.Notice("Policy Authority Starting")

	// Setup policy db
	padb, err := NewPolicyAuthorityDatabaseImpl(dbMap)
	if err != nil {
		return nil, err
	}
	pa := PolicyAuthorityImpl{
		log:              logger,
		DB:               padb,
		EnforceWhitelist: enforceWhitelist,
		PublicSuffixList: PublicSuffixList,
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
	whitelistedPartnerRegID = -1
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

// InvalidIdentifierError indicates that we didn't understand the IdentifierType
// provided.
type InvalidIdentifierError struct{}

// SyntaxError indicates that the user input was not well formatted.
type SyntaxError struct{}

// NonPublicError indicates that one or more identifiers were not on the public
// Internet.
type NonPublicError struct{}

// ErrBlacklisted indicates we have blacklisted one or more of these
// identifiers.
var ErrBlacklisted = errors.New("Name is blacklisted")

// ErrNotWhitelisted indicates we have not whitelisted one or more of these
// identifiers.
var ErrNotWhitelisted = errors.New("Name is not whitelisted")

func (e InvalidIdentifierError) Error() string { return "Invalid identifier type" }
func (e SyntaxError) Error() string            { return "Syntax error" }
func (e NonPublicError) Error() string         { return "Name does not end in a public suffix" }

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
// XXX: Is there any need for this method to be constant-time?  We're
//      going to refuse to issue anyway, but timing could leak whether
//      names are on the blacklist.
func (pa PolicyAuthorityImpl) WillingToIssue(id core.AcmeIdentifier, regID int64) error {
	if id.Type != core.IdentifierDNS {
		return InvalidIdentifierError{}
	}
	domain := id.Value

	for _, ch := range []byte(domain) {
		if !isDNSCharacter(ch) {
			return SyntaxError{}
		}
	}

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
		if len(label) < 1 || len(label) > maxLabelLength {
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
func (pa PolicyAuthorityImpl) ChallengesFor(identifier core.AcmeIdentifier, accountKey *jose.JsonWebKey) (challenges []core.Challenge, combinations [][]int, err error) {
	// TODO(https://github.com/letsencrypt/boulder/issues/894): Update these lines
	challenges = []core.Challenge{
		core.SimpleHTTPChallenge(accountKey),
		core.DvsniChallenge(accountKey),
		core.HTTPChallenge01(accountKey),
		core.TLSSNIChallenge01(accountKey),
	}
	combinations = [][]int{[]int{0}, []int{1}, []int{2}, []int{3}}
	return
}
