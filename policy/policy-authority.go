// Copyright 2014 ISRG.  All rights reserved
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/letsencrypt/boulder/core"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/reloader"
	"github.com/letsencrypt/net/publicsuffix"
	"github.com/square/go-jose"
	"gopkg.in/gorp.v1"
)

// AuthorityImpl enforces CA policy decisions.
type AuthorityImpl struct {
	log blog.Logger
	DB  *AuthorityDatabaseImpl

	blacklist   map[string]bool
	blacklistMu sync.RWMutex

	enabledChallenges map[string]bool
	pseudoRNG         *rand.Rand
}

// New constructs a Policy Authority.
// TODO(https://github.com/letsencrypt/boulder/issues/1616): Remove the _ bool
// argument (used to be enforceWhitelist). Update all callers.
func New(dbMap *gorp.DbMap, _ bool, challengeTypes map[string]bool) (*AuthorityImpl, error) {
	logger := blog.Get()

	var padb *AuthorityDatabaseImpl
	if dbMap != nil {
		// Setup policy db
		var err error
		padb, err = NewAuthorityDatabaseImpl(dbMap)
		if err != nil {
			return nil, err
		}
	}

	pa := AuthorityImpl{
		log:               logger,
		DB:                padb,
		enabledChallenges: challengeTypes,
		// We don't need real randomness for this.
		pseudoRNG: rand.New(rand.NewSource(99)),
	}

	return &pa, nil
}

type blacklistJSON struct {
	Blacklist []string
}

// SetHostnamePolicyFile will load the given policy file, returning error if it
// fails. It will also start a reloader in case the file changes.
func (pa *AuthorityImpl) SetHostnamePolicyFile(f string) error {
	_, err := reloader.New(f, pa.loadHostnamePolicy, pa.hostnamePolicyLoadError)
	return err
}

func (pa *AuthorityImpl) hostnamePolicyLoadError(err error) {
	pa.log.Err(fmt.Sprintf("error loading hostname policy: %s", err))
}

func (pa *AuthorityImpl) loadHostnamePolicy(b []byte) error {
	hash := sha256.Sum256(b)
	pa.log.Info(fmt.Sprintf("loading hostname policy, sha256: %s",
		hex.EncodeToString(hash[:])))
	var bl blacklistJSON
	err := json.Unmarshal(b, &bl)
	if err != nil {
		return err
	}
	if len(bl.Blacklist) == 0 {
		return fmt.Errorf("No entries in blacklist.")
	}
	nameMap := make(map[string]bool)
	for _, v := range bl.Blacklist {
		nameMap[v] = true
	}
	pa.blacklistMu.Lock()
	pa.blacklist = nameMap
	pa.blacklistMu.Unlock()
	return nil
}

const (
	maxLabels = 10

	// RFC 1034 says DNS labels have a max of 63 octets, and names have a max of 255
	// octets: https://tools.ietf.org/html/rfc1035#page-10
	maxLabelLength         = 63
	maxDNSIdentifierLength = 255

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
	errBlacklisted         = core.MalformedRequestError("Policy forbids issuing for name")
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
func (pa *AuthorityImpl) WillingToIssue(id core.AcmeIdentifier, regID int64) error {
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

	if len(domain) > maxDNSIdentifierLength {
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

	// Require no match against blacklist
	if err := pa.checkHostLists(domain); err != nil {
		return err
	}

	return nil
}

func (pa *AuthorityImpl) checkHostLists(domain string) error {
	if pa.DB != nil {
		return pa.DB.CheckHostLists(domain, false)
	}

	pa.blacklistMu.RLock()
	defer pa.blacklistMu.RUnlock()

	if pa.blacklist == nil {
		return fmt.Errorf("Hostname policy not yet loaded.")
	}

	labels := strings.Split(domain, ".")
	for i := range labels {
		joined := strings.Join(labels[i:], ".")
		if pa.blacklist[joined] {
			return errBlacklisted
		}
	}
	return nil
}

// ChallengesFor makes a decision of what challenges, and combinations, are
// acceptable for the given identifier.
//
// Note: Current implementation is static, but future versions may not be.
func (pa *AuthorityImpl) ChallengesFor(identifier core.AcmeIdentifier, accountKey *jose.JsonWebKey) ([]core.Challenge, [][]int) {
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

	return shuffled, shuffledCombos
}
