//go:build integration

package integration

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestDuplicateFQDNRateLimit(t *testing.T) {
	t.Parallel()
	domain := random_domain()

	// The global rate limit for a duplicate certificates is 2 per 3 hours.
	_, err := authAndIssue(nil, nil, []string{domain}, true)
	test.AssertNotError(t, err, "Failed to issue first certificate")

	_, err = authAndIssue(nil, nil, []string{domain}, true)
	test.AssertNotError(t, err, "Failed to issue second certificate")

	_, err = authAndIssue(nil, nil, []string{domain}, true)
	test.AssertError(t, err, "Somehow managed to issue third certificate")

	if strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		// Error should be served from key-value rate limits implementation.
		test.AssertContains(t, err.Error(), "too many certificates (2) already issued for this exact set of domains in the last 3h0m0s")
	} else {
		// Error should be served from legacy rate limits implementation.
		test.AssertContains(t, err.Error(), "too many certificates (2) already issued for this exact set of domains in the last 3 hours")
	}
}

func TestCertificatesPerDomain(t *testing.T) {
	t.Parallel()

	randomDomain := random_domain()
	randomSubDomain := func() string {
		var bytes [3]byte
		rand.Read(bytes[:])
		return fmt.Sprintf("%s.%s", hex.EncodeToString(bytes[:]), randomDomain)
	}

	_, err := authAndIssue(nil, nil, []string{randomSubDomain()}, true)
	test.AssertNotError(t, err, "Failed to issue first certificate")

	_, err = authAndIssue(nil, nil, []string{randomSubDomain()}, true)
	test.AssertNotError(t, err, "Failed to issue second certificate")

	_, err = authAndIssue(nil, nil, []string{randomSubDomain()}, true)
	test.AssertError(t, err, "Somehow managed to issue third certificate")

	if strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		// Error should be served from key-value rate limits implementation.
		test.AssertContains(t, err.Error(), fmt.Sprintf("too many certificates (2) already issued for %q in the last 2160h0m0s", randomDomain))
	} else {
		// Error should be served from legacy rate limits implementation.
		test.AssertContains(t, err.Error(), fmt.Sprintf("too many certificates already issued for %q", randomDomain))
	}
}

func TestRenewalExemption(t *testing.T) {
	t.Parallel()

	// Issue two certificates for different subdomains under a single domain,
	// then renew both. With the certificatesPerName limit at 2 per 90 days, and
	// renewals not exempt, both issuances should succeed. Finally, issue a
	// certificate for a third subdomain, which should fail due to the limit.

	baseDomain := random_domain()

	_, err := authAndIssue(nil, nil, []string{"www." + baseDomain}, true)
	test.AssertNotError(t, err, "Failed to issue first certificate")

	_, err = authAndIssue(nil, nil, []string{"www." + baseDomain}, true)
	test.AssertNotError(t, err, "Failed to issue first renewal")

	_, err = authAndIssue(nil, nil, []string{"blog." + baseDomain}, true)
	test.AssertNotError(t, err, "Failed to issue second certificate")

	_, err = authAndIssue(nil, nil, []string{"blog." + baseDomain}, true)
	test.AssertNotError(t, err, "Failed to issue second renewal")

	_, err = authAndIssue(nil, nil, []string{"mail." + baseDomain}, true)
	test.AssertError(t, err, "Somehow managed to issue third certificate")

	if strings.Contains(os.Getenv("BOULDER_CONFIG_DIR"), "test/config-next") {
		// Error should be served from key-value rate limits implementation.
		test.AssertContains(t, err.Error(), fmt.Sprintf("too many certificates (2) already issued for %q in the last 2160h0m0s", baseDomain))
	} else {
		// Error should be served from legacy rate limits implementation.
		test.AssertContains(t, err.Error(), fmt.Sprintf("too many certificates already issued for %q", baseDomain))
	}
}
