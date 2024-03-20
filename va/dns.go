package va

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/identifier"
)

// getAddr will query for all A/AAAA records associated with hostname and return
// the preferred address, the first net.IP in the addrs slice, and all addresses
// resolved. This is the same choice made by the Go internal resolution library
// used by net/http. If there is an error resolving the hostname, or if no
// usable IP addresses are available then a berrors.DNSError instance is
// returned with a nil net.IP slice.
func (va ValidationAuthorityImpl) getAddrs(ctx context.Context, hostname string) ([]net.IP, bdns.ResolverAddrs, error) {
	addrs, resolvers, err := va.dnsClient.LookupHost(ctx, hostname)
	if err != nil {
		return nil, resolvers, berrors.DNSError("%v", err)
	}

	if len(addrs) == 0 {
		// This should be unreachable, as no valid IP addresses being found results
		// in an error being returned from LookupHost.
		return nil, resolvers, berrors.DNSError("No valid IP addresses found for %s", hostname)
	}
	va.log.Debugf("Resolved addresses for %s: %s", hostname, addrs)
	return addrs, resolvers, nil
}

// availableAddresses takes a ValidationRecord and splits the AddressesResolved
// into a list of IPv4 and IPv6 addresses.
func availableAddresses(allAddrs []net.IP) (v4 []net.IP, v6 []net.IP) {
	for _, addr := range allAddrs {
		if addr.To4() != nil {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}
	return
}

// validateTXT will query for all TXT records associated with challengeSubdomain and
// return a ValidationRecord if the authorizedKeysDigest is found in the TXT records.
func (va *ValidationAuthorityImpl) validateTXT(
	ctx context.Context,
	ident identifier.ACMEIdentifier,
	authorizedKeysDigest string,
	challengeSubdomain string,
) ([]core.ValidationRecord, error) {
	// Look for the required record in the DNS
	txts, resolvers, err := va.dnsClient.LookupTXT(ctx, challengeSubdomain)
	if err != nil {
		return nil, berrors.DNSError("%s", err)
	}

	// If there weren't any TXT records return a distinct error message to allow
	// troubleshooters to differentiate between no TXT records and
	// invalid/incorrect TXT records.
	if len(txts) == 0 {
		return nil, berrors.UnauthorizedError("No TXT record found at %s", challengeSubdomain)
	}

	for _, element := range txts {
		if subtle.ConstantTimeCompare([]byte(element), []byte(authorizedKeysDigest)) == 1 {
			// Successful challenge validation
			return []core.ValidationRecord{{Hostname: ident.Value, ResolverAddrs: resolvers}}, nil
		}
	}

	invalidRecord := txts[0]
	if len(invalidRecord) > 100 {
		invalidRecord = invalidRecord[0:100] + "..."
	}
	var andMore string
	if len(txts) > 1 {
		andMore = fmt.Sprintf(" (and %d more)", len(txts)-1)
	}
	return nil, berrors.UnauthorizedError("Incorrect TXT record %q%s found at %s",
		invalidRecord, andMore, challengeSubdomain)
}

func (va *ValidationAuthorityImpl) validateDNS01(ctx context.Context, ident identifier.ACMEIdentifier, challenge core.Challenge) ([]core.ValidationRecord, error) {
	if ident.Type != identifier.DNS {
		va.log.Infof("Identifier type for DNS challenge was not DNS: %s", ident)
		return nil, berrors.MalformedError("Identifier type for DNS was not itself DNS")
	}

	// Compute the digest of the key authorization file
	h := sha256.New()
	h.Write([]byte(challenge.ProvidedKeyAuthorization))
	authorizedKeysDigest := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Look for the required record in the DNS
	challengeSubdomain := fmt.Sprintf("%s.%s", core.DNSPrefix, ident.Value)

	// Return the validation record if the correct TXT record is found
	return va.validateTXT(ctx, ident, authorizedKeysDigest, challengeSubdomain)
}

// Compute the DNS-ACCOUNT-01 challenge subdomain per the
// acme-scoped-dns-challenges specification
func getDNSAccountChallengeSubdomain(
	accountResourceURL string,
	scope core.AuthorizationScope,
	domain string,
) string {
	// "_" || base32(SHA-256(<ACCOUNT_RESOURCE_URL>)[0:10]) || "._acme-" || <SCOPE> || "-challenge"
	acctHash := sha256.Sum256([]byte(accountResourceURL))
	acctLabel := strings.ToLower(base32.StdEncoding.EncodeToString(acctHash[0:10]))
	challengeSubdomain := fmt.Sprintf("_%s._acme-%s-challenge.%s",
		acctLabel, scope, domain)

	return challengeSubdomain
}

// validateDNSAccount01 validates a DNS-ACCOUNT-01 challenge using the account's URI
// (derived from the accountID) and the authorization scope.
func (va *ValidationAuthorityImpl) validateDNSAccount01(ctx context.Context,
	ident identifier.ACMEIdentifier,
	challenge core.Challenge,
) ([]core.ValidationRecord, error) {
	if ident.Type != identifier.DNS {
		va.log.Infof("Identifier type for DNS challenge was not DNS: %s", ident)
		return nil, berrors.MalformedError("Identifier type for DNS was not itself DNS")
	}

	// Reject unsupported scopes
	if challenge.Scope != core.AuthorizationScopeHost && challenge.Scope != core.AuthorizationScopeWildcard {
		va.log.Infof("Unsupported scope for DNS-ACCOUNT-01 challenge: %s", challenge.Scope)
		return nil, berrors.MalformedError("Unsupported scope for DNS-ACCOUNT-01 challenge")
	}

	// Compute the digest of the key authorization file
	h := sha256.New()
	h.Write([]byte(challenge.ProvidedKeyAuthorization))
	authorizedKeysDigest := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Compute the challenge subdomain for this account
	challengeSubdomain := getDNSAccountChallengeSubdomain(challenge.AccountURL, challenge.Scope, ident.Value)

	// Look for the required record in the DNS
	validationRecords, err := va.validateTXT(ctx, ident, authorizedKeysDigest, challengeSubdomain)
	if err == nil {
		// Successful challenge validation
		return validationRecords, nil
	}

	// Return error from last accountURIPrefix attempted
	return nil, err
}
