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

	"github.com/weppos/publicsuffix-go/publicsuffix"
	"golang.org/x/net/idna"

	"github.com/letsencrypt/boulder/core"
	"github.com/letsencrypt/boulder/features"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/probs"
	"github.com/letsencrypt/boulder/reloader"
)

// AuthorityImpl enforces CA policy decisions.
type AuthorityImpl struct {
	log blog.Logger

	blacklist      map[string]bool
	exactBlacklist map[string]bool
	blacklistMu    sync.RWMutex

	enabledChallenges map[string]bool
	pseudoRNG         *rand.Rand
}

// New constructs a Policy Authority.
// TODO(https://github.com/letsencrypt/boulder/issues/1616): Remove the _ bool
// argument (used to be enforceWhitelist). Update all callers.
func New(challengeTypes map[string]bool) (*AuthorityImpl, error) {

	pa := AuthorityImpl{
		log:               blog.Get(),
		enabledChallenges: challengeTypes,
		// We don't need real randomness for this.
		pseudoRNG: rand.New(rand.NewSource(99)),
	}

	return &pa, nil
}

type blacklistJSON struct {
	Blacklist      []string
	ExactBlacklist []string
}

// SetHostnamePolicyFile will load the given policy file, returning error if it
// fails. It will also start a reloader in case the file changes.
func (pa *AuthorityImpl) SetHostnamePolicyFile(f string) error {
	_, err := reloader.New(f, pa.loadHostnamePolicy, pa.hostnamePolicyLoadError)
	return err
}

func (pa *AuthorityImpl) hostnamePolicyLoadError(err error) {
	pa.log.AuditErr(fmt.Sprintf("error loading hostname policy: %s", err))
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
	exactNameMap := make(map[string]bool)
	for _, v := range bl.ExactBlacklist {
		exactNameMap[v] = true
	}
	pa.blacklistMu.Lock()
	pa.blacklist = nameMap
	pa.exactBlacklist = exactNameMap
	pa.blacklistMu.Unlock()
	return nil
}

const (
	maxLabels = 10

	// RFC 1034 says DNS labels have a max of 63 octets, and names have a max of 255
	// octets: https://tools.ietf.org/html/rfc1035#page-10
	maxLabelLength         = 63
	maxDNSIdentifierLength = 255
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
	errInvalidIdentifier   = probs.Malformed("Invalid identifier type")
	errNonPublic           = probs.Malformed("Name does not end in a public suffix")
	errICANNTLD            = probs.Malformed("Name is an ICANN TLD")
	errBlacklisted         = probs.RejectedIdentifier("Policy forbids issuing for name")
	errNotWhitelisted      = probs.Malformed("Name is not whitelisted")
	errInvalidDNSCharacter = probs.Malformed("Invalid character in DNS name")
	errNameTooLong         = probs.Malformed("DNS name too long")
	errIPAddress           = probs.Malformed("Issuance for IP addresses not supported")
	errTooManyLabels       = probs.Malformed("DNS name has too many labels")
	errEmptyName           = probs.Malformed("DNS name was empty")
	errTooFewLabels        = probs.Malformed("DNS name does not have enough labels")
	errLabelTooShort       = probs.Malformed("DNS label is too short")
	errLabelTooLong        = probs.Malformed("DNS label is too long")
	errIDNNotSupported     = probs.UnsupportedIdentifier("Internationalized domain names (starting with xn--) not yet supported")
	errMalformedIDN        = probs.Malformed("DNS label contains malformed punycode")
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
func (pa *AuthorityImpl) WillingToIssue(id core.AcmeIdentifier) error {
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
			if features.Enabled(features.IDNASupport) {
				// We don't care about script usage, if a name is resolvable it was
				// registered with a higher power and they should be enforcing their
				// own policy. As long as it was properly encoded that is enough
				// for us.
				_, err := idna.ToUnicode(label)
				if err != nil {
					return errMalformedIDN
				}
			} else {
				return errIDNNotSupported
			}
		}
	}

	unicodeDomain := domain
	if features.Enabled(features.IDNASupport) {
		var err error
		unicodeDomain, err = idna.ToUnicode(domain)
		if err != nil {
			return errMalformedIDN
		}
	}
	// Names must end in an ICANN TLD, but they must not be equal to an ICANN TLD.
	icannTLD, err := extractDomainIANASuffix(unicodeDomain)
	if err != nil {
		return errNonPublic
	}
	if icannTLD == unicodeDomain {
		return errICANNTLD
	}

	// Require no match against blacklist
	if err := pa.checkHostLists(domain); err != nil {
		return err
	}

	return nil
}

func (pa *AuthorityImpl) checkHostLists(domain string) error {
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

	if pa.exactBlacklist[domain] {
		return errBlacklisted
	}
	return nil
}

// ChallengesFor makes a decision of what challenges, and combinations, are
// acceptable for the given identifier.
//
// Note: Current implementation is static, but future versions may not be.
func (pa *AuthorityImpl) ChallengesFor(identifier core.AcmeIdentifier) ([]core.Challenge, [][]int) {
	challenges := []core.Challenge{}

	if pa.enabledChallenges[core.ChallengeTypeHTTP01] {
		challenges = append(challenges, core.HTTPChallenge01())
	}

	if pa.enabledChallenges[core.ChallengeTypeTLSSNI01] {
		challenges = append(challenges, core.TLSSNIChallenge01())
	}

	if pa.enabledChallenges[core.ChallengeTypeDNS01] {
		challenges = append(challenges, core.DNSChallenge01())
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

// ExtractDomainIANASuffix returns the public suffix of the domain using only the "ICANN"
// section of the Public Suffix List database.
// If the domain does not end in a suffix that belongs to an IANA-assigned
// domain, ExtractDomainIANASuffix returns an error.
func extractDomainIANASuffix(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("Blank name argument passed to ExtractDomainIANASuffix")
	}

	rule := publicsuffix.DefaultList.Find(name, &publicsuffix.FindOptions{IgnorePrivate: true, DefaultRule: nil})
	if rule == nil {
		return "", fmt.Errorf("Domain %s has no IANA TLD", name)
	}

	suffix := rule.Decompose(name)[1]

	// If the TLD is empty, it means name is actually a suffix.
	// In fact, decompose returns an array of empty strings in this case.
	if suffix == "" {
		suffix = name
	}

	return suffix, nil
}
