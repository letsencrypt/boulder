// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
)

type PolicyAuthorityImpl struct {
	log *blog.AuditLogger

	IssuerDomain string

	PublicSuffixList map[string]bool // A copy of the DNS root zone
	Blacklist        map[string]bool // A blacklist of denied names
}

func NewPolicyAuthorityImpl(logger *blog.AuditLogger, issuerDomain string) *PolicyAuthorityImpl {
	logger.Notice("Registration Authority Starting")

	pa := PolicyAuthorityImpl{log: logger}

	pa.IssuerDomain = issuerDomain

	// TODO: Add configurability
	pa.PublicSuffixList = publicSuffixList
	pa.Blacklist = blacklist

	return &pa
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
	for i, _ := range labels {
		if domain := strings.Join(labels[i:], "."); suffixSet[domain] {
			// If we match on the whole domain, gate on properSuffix
			return !properSuffix || (i > 0)
		}
	}
	return false
}

var InvalidIdentifierError = errors.New("Invalid identifier type")
var SyntaxError = errors.New("Syntax error")
var NonPublicError = errors.New("Name does not end in a public suffix")
var BlacklistedError = errors.New("Name is blacklisted")

var CAAError = errors.New("Error retrieving CAA records")
var UnknownCriticalCAAError = errors.New("Existing critical CAA records that cannot be parsed")
var ReservedCAAError = errors.New("Existing CAA records that dont match local issuer")

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
		return InvalidIdentifierError
	}
	domain := id.Value

	for _, ch := range []byte(domain) {
		if !isDNSCharacter(ch) {
			return SyntaxError
		}
	}

	domain = strings.ToLower(domain)
	if len(domain) > 255 {
		return SyntaxError
	}

	if ip := net.ParseIP(domain); ip != nil {
		return SyntaxError
	}

	labels := strings.Split(domain, ".")
	if len(labels) > maxLabels || len(labels) < 2 {
		return SyntaxError
	}
	for _, label := range labels {
		// DNS defines max label length as 63 characters. Some implementations allow
		// more, but we will be conservative.
		if len(label) < 1 || len(label) > 63 {
			return SyntaxError
		}

		if !dnsLabelRegexp.MatchString(label) {
			return SyntaxError
		}

		if punycodeRegexp.MatchString(label) {
			return SyntaxError
		}
	}

	// Require match to PSL, plus at least one label
	if !suffixMatch(labels, pa.PublicSuffixList, true) {
		return NonPublicError
	}

	// Require no match against blacklist
	if suffixMatch(labels, pa.Blacklist, false) {
		return BlacklistedError
	}

	return nil
}

// CheckCAARecords Does what it says on the tin
func (pa PolicyAuthorityImpl) CheckCAARecords(id core.AcmeIdentifier) error {
	domain := id.Value
	domain = strings.ToLower(domain)

	caaSet, dnssec, err := getCaaSet(domain)
	if err != nil {
		err = fmt.Errorf("[DNSSEC: %s] %s", dnssec, err)
		pa.log.AuditErr(err)
		fmt.Println(err)
		return CAAError
	}
	if caaSet == nil {
		pa.log.Audit(fmt.Sprintf("[DNSSEC: %s] Didn't find any CAA records for '%s', can issue", dnssec, domain))
		return nil
	}
	if caaSet.CriticalUnknown() {
		err = fmt.Errorf("[DNSSEC: %s] Unknown CAA properties flagged as critical for '%s', cannot issue", dnssec, domain)
		pa.log.AuditErr(err)
		return UnknownCriticalCAAError
	}

	if len(caaSet.issue) > 0 || len(caaSet.issuewild) > 0 {
		var correctSet []*CAA
		if strings.SplitN(domain, ".", 2)[0] == "*" {
			correctSet = caaSet.issuewild
		} else {
			correctSet = caaSet.issue
		}
		if len(correctSet) > 0 {
			for _, caa := range correctSet {
				if caa.value == pa.IssuerDomain {
					pa.log.Audit(fmt.Sprintf("[DNSSEC: %s] Found issue/issuewild CAA record for '%s' matching local issuer '%s', can issue", dnssec, domain, pa.IssuerDomain))
					return nil
				}
			}
		}

		err = fmt.Errorf("[DNSSEC: %s] Local issuer '%s' did not match any CAA records for '%s', cannot issue", dnssec, pa.IssuerDomain, domain)
		pa.log.AuditErr(err)
		return ReservedCAAError
	}

	pa.log.Audit(fmt.Sprintf("[DNSSEC: %s] Didn't find any CAA records for '%s', can issue", dnssec, domain))
	return nil
}

// For now, we just issue DVSNI and SimpleHTTPS challenges for everything
func (pa PolicyAuthorityImpl) ChallengesFor(identifier core.AcmeIdentifier) (challenges []core.Challenge, combinations [][]int) {
	challenges = []core.Challenge{
		core.SimpleHTTPSChallenge(),
		core.DvsniChallenge(),
	}
	combinations = [][]int{
		[]int{0},
		[]int{1},
	}
	return
}
