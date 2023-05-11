//go:build integration

package integration

import (
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
}
