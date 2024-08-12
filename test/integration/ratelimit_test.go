//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/cmd"
	berrors "github.com/letsencrypt/boulder/errors"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/ratelimits"
	bredis "github.com/letsencrypt/boulder/redis"
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
		// Setup rate limiting.
		rc := bredis.Config{
			Username: "unittest-rw",
			TLS: cmd.TLSConfig{
				CACertFile: "test/certs/ipki/minica.pem",
				CertFile:   "test/certs/ipki/localhost/cert.pem",
				KeyFile:    "test/certs/ipki/localhost/key.pem",
			},
			Lookups: []cmd.ServiceDomain{
				{
					Service: "redisratelimits",
					Domain:  "service.consul",
				},
			},
			LookupDNSAuthority: "consul.service.consul",
		}
		rc.PasswordConfig = cmd.PasswordConfig{
			PasswordFile: "test/secrets/ratelimits_redis_password",
		}

		fc := clock.New()
		stats := metrics.NoopRegisterer
		log := blog.NewMock()
		ring, err := bredis.NewRingFromConfig(rc, stats, log)
		test.AssertNotError(t, err, "making redis ring client")
		source := ratelimits.NewRedisSource(ring.Ring, fc, stats)
		test.AssertNotNil(t, source, "source should not be nil")
		limiter, err := ratelimits.NewLimiter(fc, source, stats)
		test.AssertNotError(t, err, "making limiter")
		txnBuilder, err := ratelimits.NewTransactionBuilder("test/config-next/wfe2-ratelimit-defaults.yml", "")
		test.AssertNotError(t, err, "making transaction composer")

		// Check that the CertificatesPerFQDNSet limit is reached.
		txns, err := txnBuilder.NewOrderLimitTransactions(1, []string{domain}, 100, false)
		test.AssertNotError(t, err, "making transaction")
		decision, err := limiter.BatchSpend(context.Background(), txns)
		test.AssertNotError(t, err, "checking transaction")
		err = decision.Result(fc.Now())
		test.AssertErrorIs(t, err, berrors.RateLimit)
		test.AssertContains(t, err.Error(), "too many certificates (2) already issued for this exact set of domains in the last 3h0m0s")
	}
}
