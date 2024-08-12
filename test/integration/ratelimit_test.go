//go:build integration

package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/test"
)

func TestDuplicateFQDNRateLimit(t *testing.T) {
	t.Parallel()
	domain := random_domain()

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
