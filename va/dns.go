package va

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/letsencrypt/boulder/bdns"
	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/identifier"
)

// getAddr will query for all A/AAAA records associated with hostname and return
// the preferred address, the first netip.Addr in the addrs slice, and all
// addresses resolved. This is the same choice made by the Go internal
// resolution library used by net/http. If there is an error resolving the
// hostname, or if no usable IP addresses are available then a berrors.DNSError
// instance is returned with a nil netip.Addr slice.
func (va ValidationAuthorityImpl) getAddrs(ctx context.Context, hostname string) ([]netip.Addr, bdns.ResolverAddrs, error) {
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
func availableAddresses(allAddrs []netip.Addr) (v4 []netip.Addr, v6 []netip.Addr) {
	for _, addr := range allAddrs {
		if addr.Is4() {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}
	return
}

// validateDNSAccount01 handles the dns-account-01 challenge by calculating
// the account-specific DNS query domain and expected digest, then calling
// the common DNS validation logic.
// This implements draft-ietf-acme-dns-account-label-01, and is permitted by
// CAB/F Ballot SC-84, which was incorporated into BR v2.1.4.
func (va *ValidationAuthorityImpl) validateDNSAccount01(ctx context.Context, ident identifier.ACMEIdentifier, keyAuthorization string, accountURI string) ([]core.ValidationRecord, error) {
	if ident.Type != identifier.TypeDNS {
		return nil, berrors.MalformedError("Identifier type for DNS-ACCOUNT-01 challenge was not DNS")
	}
	if accountURI == "" {
		return nil, berrors.InternalServerError("accountURI must be provided for dns-account-01")
	}

	// Calculate the DNS prefix label based on the account URI
	sha256sum := sha256.Sum256([]byte(accountURI))
	prefixBytes := sha256sum[0:10] // First 10 bytes
	prefixLabel := strings.ToLower(base32.StdEncoding.EncodeToString(prefixBytes))

	// Construct the challenge prefix specific to DNS-ACCOUNT-01
	challengePrefix := fmt.Sprintf("_%s.%s", prefixLabel, core.DNSPrefix)
	va.log.Debugf("DNS-ACCOUNT-01: Querying TXT for %q (derived from account URI %q)", fmt.Sprintf("%s.%s", challengePrefix, ident.Value), accountURI)

	// Call the common validation logic
	records, err := va.validateDNS(ctx, ident, challengePrefix, keyAuthorization)
	if err != nil {
		// Check if the error returned by validateDNS is of the Unauthorized type
		if errors.Is(err, berrors.Unauthorized) {
			// Enrich any UnauthorizedError from validateDNS with the account URI
			enrichedError := berrors.UnauthorizedError("%s (account: %q)", err.Error(), accountURI)
			return nil, enrichedError
		}
		// For other error types, return as is
		return nil, err
	}

	return records, nil
}

func (va *ValidationAuthorityImpl) validateDNS01(ctx context.Context, ident identifier.ACMEIdentifier, keyAuthorization string) ([]core.ValidationRecord, error) {
	if ident.Type != identifier.TypeDNS {
		return nil, berrors.MalformedError("Identifier type for DNS-01 challenge was not DNS")
	}

	// Call the common validation logic
	return va.validateDNS(ctx, ident, core.DNSPrefix, keyAuthorization)
}

// validateDNS performs the DNS TXT lookup and validation logic.
func (va *ValidationAuthorityImpl) validateDNS(ctx context.Context, ident identifier.ACMEIdentifier, challengePrefix string, keyAuthorization string) ([]core.ValidationRecord, error) {
	// Compute the digest of the key authorization file
	h := sha256.New()
	h.Write([]byte(keyAuthorization))
	authorizedKeysDigest := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Construct the full challenge subdomain by concatenating prefix with identifier
	challengeSubdomain := fmt.Sprintf("%s.%s", challengePrefix, ident.Value)

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
		if element == authorizedKeysDigest {
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
