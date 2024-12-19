//go:build integration

package integration

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
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

	test.AssertContains(t, err.Error(), "too many certificates (2) already issued for this exact set of domains in the last 3h0m0s")
}

func TestCertificatesPerDomain(t *testing.T) {
	t.Parallel()

	randomDomain := random_domain()
	randomSubDomain := func() string {
		var bytes [3]byte
		rand.Read(bytes[:])
		return fmt.Sprintf("%s.%s", hex.EncodeToString(bytes[:]), randomDomain)
	}

	firstSubDomain := randomSubDomain()
	_, err := authAndIssue(nil, nil, []string{firstSubDomain}, true)
	test.AssertNotError(t, err, "Failed to issue first certificate")

	_, err = authAndIssue(nil, nil, []string{randomSubDomain()}, true)
	test.AssertNotError(t, err, "Failed to issue second certificate")

	_, err = authAndIssue(nil, nil, []string{randomSubDomain()}, true)
	test.AssertError(t, err, "Somehow managed to issue third certificate")

	test.AssertContains(t, err.Error(), fmt.Sprintf("too many certificates (2) already issued for %q in the last 2160h0m0s", randomDomain))

	// Issue a certificate for the first subdomain, which should succeed because
	// it's a renewal.
	_, err = authAndIssue(nil, nil, []string{firstSubDomain}, true)
	test.AssertNotError(t, err, "Failed to issue renewal certificate")
}
