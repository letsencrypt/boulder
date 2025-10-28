package nonce

import (
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

func TestValidNonce(t *testing.T) {
	ns, err := NewNonceService(metrics.NoopRegisterer, 0, "")
	test.AssertNotError(t, err, "Could not create nonce service")
	n, err := ns.nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.AssertNotError(t, ns.valid(n), fmt.Sprintf("Did not recognize fresh nonce %s", n))
	test.AssertMetricWithLabelsEquals(t, ns.nonceRedeems, prometheus.Labels{
		"result": "valid", "error": "",
	}, 1)
	test.AssertHistogramBucketCount(t, ns.nonceAges, prometheus.Labels{
		"result": "valid",
	}, 0, 1)
}

func TestAlreadyUsed(t *testing.T) {
	ns, err := NewNonceService(metrics.NoopRegisterer, 0, "")
	test.AssertNotError(t, err, "Could not create nonce service")
	n, err := ns.nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.AssertNotError(t, ns.valid(n), "Did not recognize fresh nonce")
	test.AssertError(t, ns.valid(n), "Recognized the same nonce twice")
	test.AssertMetricWithLabelsEquals(t, ns.nonceRedeems, prometheus.Labels{
		"result": "invalid", "error": "already used",
	}, 1)
	test.AssertHistogramBucketCount(t, ns.nonceAges, prometheus.Labels{
		"result": "invalid",
	}, 0, 1)
}

func TestRejectMalformed(t *testing.T) {
	ns, err := NewNonceService(metrics.NoopRegisterer, 0, "")
	test.AssertNotError(t, err, "Could not create nonce service")
	n, err := ns.nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.AssertError(t, ns.valid("asdf"+n), "Accepted an invalid nonce")
	test.AssertMetricWithLabelsEquals(t, ns.nonceRedeems, prometheus.Labels{
		"result": "invalid", "error": "decrypt",
	}, 1)
}

func TestRejectShort(t *testing.T) {
	ns, err := NewNonceService(metrics.NoopRegisterer, 0, "")
	test.AssertNotError(t, err, "Could not create nonce service")
	test.AssertError(t, ns.valid("aGkK"), "Accepted an invalid nonce")
	test.AssertMetricWithLabelsEquals(t, ns.nonceRedeems, prometheus.Labels{
		"result": "invalid", "error": "decrypt",
	}, 1)
}

func TestRejectUnknown(t *testing.T) {
	ns1, err := NewNonceService(metrics.NoopRegisterer, 0, "")
	test.AssertNotError(t, err, "Could not create nonce service")
	ns2, err := NewNonceService(metrics.NoopRegisterer, 0, "")
	test.AssertNotError(t, err, "Could not create nonce service")

	n, err := ns1.nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.AssertError(t, ns2.valid(n), "Accepted a foreign nonce")
	test.AssertMetricWithLabelsEquals(t, ns2.nonceRedeems, prometheus.Labels{
		"result": "invalid", "error": "decrypt",
	}, 1)
}

func TestRejectTooLate(t *testing.T) {
	ns, err := NewNonceService(metrics.NoopRegisterer, 0, "")
	test.AssertNotError(t, err, "Could not create nonce service")

	ns.latest = 2
	n, err := ns.nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	ns.latest = 1
	test.AssertError(t, ns.valid(n), "Accepted a nonce with a too-high counter")
	test.AssertMetricWithLabelsEquals(t, ns.nonceRedeems, prometheus.Labels{
		"result": "invalid", "error": "too high",
	}, 1)
	test.AssertHistogramBucketCount(t, ns.nonceAges, prometheus.Labels{
		"result": "invalid",
	}, -1, 1)
}

func TestRejectTooEarly(t *testing.T) {
	// Use a very low value for maxUsed so the loop below can be short.
	ns, err := NewNonceService(metrics.NoopRegisterer, 2, "")
	test.AssertNotError(t, err, "Could not create nonce service")

	n, err := ns.nonce()
	test.AssertNotError(t, err, "Could not create nonce")

	// Generate and redeem enough nonces to surpass maxUsed, forcing the nonce
	// service to move ns.earliest upwards, invalidating n.
	for range ns.maxUsed + 1 {
		n, err := ns.nonce()
		test.AssertNotError(t, err, "Could not create nonce")
		test.AssertNotError(t, ns.valid(n), "Rejected a valid nonce")
	}

	test.AssertError(t, ns.valid(n), "Accepted a nonce that we should have forgotten")
	test.AssertMetricWithLabelsEquals(t, ns.nonceRedeems, prometheus.Labels{
		"result": "invalid", "error": "too low",
	}, 1)
	test.AssertHistogramBucketCount(t, ns.nonceAges, prometheus.Labels{
		"result": "invalid",
	}, 1.5, 1)
}

func TestNonceMetrics(t *testing.T) {
	// Use a low value for maxUsed so the loop below can be short.
	ns, err := NewNonceService(metrics.NoopRegisterer, 2, "")
	test.AssertNotError(t, err, "Could not create nonce service")

	// After issuing (but not redeeming) many nonces, the latest should have
	// increased by the same amount and the earliest should have moved at all.
	var nonces []string
	for range 10 * ns.maxUsed {
		n, err := ns.nonce()
		test.AssertNotError(t, err, "Could not create nonce")
		nonces = append(nonces, n)
	}
	test.AssertMetricWithLabelsEquals(t, ns.nonceEarliest, nil, 0)
	test.AssertMetricWithLabelsEquals(t, ns.nonceLatest, nil, 20)

	// Redeeming maxUsed nonces shouldn't cause either metric to change, because
	// no redeemed nonces have been dropped from the used heap yet.
	test.AssertNotError(t, ns.valid(nonces[0]), "Rejected a valid nonce")
	test.AssertNotError(t, ns.valid(nonces[1]), "Rejected a valid nonce")
	test.AssertMetricWithLabelsEquals(t, ns.nonceEarliest, nil, 0)
	test.AssertMetricWithLabelsEquals(t, ns.nonceLatest, nil, 20)

	// Redeeming one more nonce should cause the earliest to move forward one, as
	// the earliest redeemed nonce is popped from the heap.
	test.AssertNotError(t, ns.valid(nonces[2]), "Rejected a valid nonce")
	test.AssertMetricWithLabelsEquals(t, ns.nonceEarliest, nil, 1)
	test.AssertMetricWithLabelsEquals(t, ns.nonceLatest, nil, 20)

	// Redeeming maxUsed+1 much later nonces should cause the earliest to skip
	// forward to the first of those.
	test.AssertNotError(t, ns.valid(nonces[17]), "Rejected a valid nonce")
	test.AssertNotError(t, ns.valid(nonces[18]), "Rejected a valid nonce")
	test.AssertNotError(t, ns.valid(nonces[19]), "Rejected a valid nonce")
	test.AssertMetricWithLabelsEquals(t, ns.nonceEarliest, nil, 18)
	test.AssertMetricWithLabelsEquals(t, ns.nonceLatest, nil, 20)
}

func BenchmarkNonces(b *testing.B) {
	ns, err := NewNonceService(metrics.NoopRegisterer, 0, "")
	if err != nil {
		b.Fatal("creating nonce service", err)
	}

	for range ns.maxUsed {
		n, err := ns.nonce()
		if err != nil {
			b.Fatal("noncing", err)
		}
		if ns.valid(n) != nil {
			b.Fatal("generated invalid nonce")
		}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n, err := ns.nonce()
			if err != nil {
				b.Fatal("noncing", err)
			}
			if ns.valid(n) != nil {
				b.Fatal("generated invalid nonce")
			}
		}
	})
}

func TestNoncePrefixing(t *testing.T) {
	ns, err := NewNonceService(metrics.NoopRegisterer, 0, "aluminum")
	test.AssertNotError(t, err, "Could not create nonce service")

	n, err := ns.nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.AssertNotError(t, ns.valid(n), "Valid nonce rejected")

	n, err = ns.nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	n = n[1:]
	test.AssertError(t, ns.valid(n), "Valid nonce with incorrect prefix accepted")

	n, err = ns.nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.AssertError(t, ns.valid(n[6:]), "Valid nonce without prefix accepted")
}

func TestNoncePrefixValidation(t *testing.T) {
	_, err := NewNonceService(metrics.NoopRegisterer, 0, "whatsup")
	test.AssertError(t, err, "NewNonceService didn't fail with short prefix")
	_, err = NewNonceService(metrics.NoopRegisterer, 0, "whatsup!")
	test.AssertError(t, err, "NewNonceService didn't fail with invalid base64")
	_, err = NewNonceService(metrics.NoopRegisterer, 0, "whatsupp")
	test.AssertNotError(t, err, "NewNonceService failed with valid nonce prefix")
}

func TestDerivePrefix(t *testing.T) {
	prefix := DerivePrefix("192.168.1.1:8080", []byte("3b8c758dd85e113ea340ce0b3a99f389d40a308548af94d1730a7692c1874f1f"))
	test.AssertEquals(t, prefix, "P9qQaK4o")
}
