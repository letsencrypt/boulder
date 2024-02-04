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

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/probs"
)

// getAddr will query for all A/AAAA records associated with hostname and return
// the preferred address, the first net.IP in the addrs slice, and all addresses
// resolved. This is the same choice made by the Go internal resolution library
// used by net/http. If there is an error resolving the hostname, or if no
// usable IP addresses are available then a berrors.DNSError instance is
// returned with a nil net.IP slice.
func (va ValidationAuthorityImpl) getAddrs(ctx context.Context, hostname string) ([]net.IP, error) {
	addrs, err := va.dnsClient.LookupHost(ctx, hostname)
	if err != nil {
		return nil, berrors.DNSError("%v", err)
	}

	if len(addrs) == 0 {
		// This should be unreachable, as no valid IP addresses being found results
		// in an error being returned from LookupHost.
		return nil, berrors.DNSError("No valid IP addresses found for %s", hostname)
	}
	va.log.Debugf("Resolved addresses for %s: %s", hostname, addrs)
	return addrs, nil
}

func accountURLHostname(AccountURLPrefixes []string, ident identifier.ACMEIdentifier, regid int64) []string {
	const dnsacc01Prefix = "_acme-challenge_"
	var testdomains []string
	for _, prefix := range AccountURLPrefixes {
		accturl := fmt.Sprintf("%s%d", prefix, regid)
		hash := sha256.Sum256([]byte(accturl))
		urlhash := strings.ToLower(base32.StdEncoding.EncodeToString(hash[0:10]))
		testdomain := fmt.Sprintf("%s%s.%s", dnsacc01Prefix, urlhash, ident.Value)
		testdomains = append(testdomains, testdomain)
	}
	return testdomains
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

func (va *ValidationAuthorityImpl) validateDNS01(ctx context.Context, ident identifier.ACMEIdentifier, challenge core.Challenge) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if ident.Type != identifier.DNS {
		va.log.Infof("Identifier type for DNS challenge was not DNS: %s", ident)
		return nil, probs.Malformed("Identifier type for DNS was not itself DNS")
	}

	// Compute the digest of the key authorization file
	h := sha256.New()
	h.Write([]byte(challenge.ProvidedKeyAuthorization))
	authorizedKeysDigest := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	// Look for the required record in the DNS
	challengeSubdomain := fmt.Sprintf("%s.%s", core.DNSPrefix, ident.Value)

	return va.validateDNSsingle(ctx, ident, authorizedKeysDigest, challengeSubdomain)
}

func (va *ValidationAuthorityImpl) validateDNSsingle(ctx context.Context, ident identifier.ACMEIdentifier,
	authorizedKeysDigest string, challengeSubdomain string) ([]core.ValidationRecord, *probs.ProblemDetails) {

	txts, err := va.dnsClient.LookupTXT(ctx, challengeSubdomain)
	if err != nil {
		return nil, probs.DNS(err.Error())
	}

	// If there weren't any TXT records return a distinct error message to allow
	// troubleshooters to differentiate between no TXT records and
	// invalid/incorrect TXT records.
	if len(txts) == 0 {
		return nil, probs.Unauthorized(fmt.Sprintf("No TXT record found at %s", challengeSubdomain))
	}

	for _, element := range txts {
		if subtle.ConstantTimeCompare([]byte(element), []byte(authorizedKeysDigest)) == 1 {
			// Successful challenge validation
			return []core.ValidationRecord{{Hostname: ident.Value}}, nil
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
	return nil, probs.Unauthorized(fmt.Sprintf("Incorrect TXT record %q%s found at %s",
		invalidRecord, andMore, challengeSubdomain))
}

func (va *ValidationAuthorityImpl) validateDNSAccount01(ctx context.Context, ident identifier.ACMEIdentifier, challenge core.Challenge, regid int64) ([]core.ValidationRecord, *probs.ProblemDetails) {
	if ident.Type != identifier.DNS {
		va.log.Infof("Identifier type for DNS challenge was not DNS: %s", ident)
		return nil, probs.Malformed("Identifier type for DNS was not itself DNS")
	}
	if regid == 0 {
		return nil, probs.Malformed("got request for invalid account context")
	}
	// Compute the digest of the key authorization file
	h := sha256.New()
	h.Write([]byte(challenge.ProvidedKeyAuthorization))
	authorizedKeysDigest := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	//we don't know what accountURIPrefixes client used so we have to try all
	challengeSubdomains := accountURLHostname(va.accountURIPrefixes, ident, regid)
	var problems []*probs.ProblemDetails
	// for all valid accounturl hostname we try hash of those
	for _, csub := range challengeSubdomains {
		res, err := va.validateDNSsingle(ctx, ident, authorizedKeysDigest, csub)
		if err == nil {
			return res, nil
		} else {
			problems = append(problems, err)
		}
	} //now everything returned error, what accountURLprefix client used?
	if len(problems) == 1 {
		return nil, problems[0] //there was only one name on prefix return that
	}
	//return last one because it's v2 accounturl and what most account would have
	//TODO:actually trace request account URL from WFE and use this, or prefer txt than nxdomain
	return nil, problems[len(problems)-1]
}
