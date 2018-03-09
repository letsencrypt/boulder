package nonce

import (
	"fmt"
	"testing"

	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

func TestValidNonce(t *testing.T) {
	ns, err := NewNonceService(metrics.NewNoopScope())
	test.AssertNotError(t, err, "Could not create nonce service")
	n, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.Assert(t, ns.Valid(n), fmt.Sprintf("Did not recognize fresh nonce %s", n))
}

func TestAlreadyUsed(t *testing.T) {
	ns, err := NewNonceService(metrics.NewNoopScope())
	test.AssertNotError(t, err, "Could not create nonce service")
	n, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.Assert(t, ns.Valid(n), "Did not recognize fresh nonce")
	test.Assert(t, !ns.Valid(n), "Recognized the same nonce twice")
}

func TestRejectMalformed(t *testing.T) {
	ns, err := NewNonceService(metrics.NewNoopScope())
	test.AssertNotError(t, err, "Could not create nonce service")
	n, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.Assert(t, !ns.Valid("asdf"+n), "Accepted an invalid nonce")
}

func TestRejectShort(t *testing.T) {
	ns, err := NewNonceService(metrics.NewNoopScope())
	test.AssertNotError(t, err, "Could not create nonce service")
	test.Assert(t, !ns.Valid("aGkK"), "Accepted an invalid nonce")
}

func TestRejectUnknown(t *testing.T) {
	ns1, err := NewNonceService(metrics.NewNoopScope())
	test.AssertNotError(t, err, "Could not create nonce service")
	ns2, err := NewNonceService(metrics.NewNoopScope())
	test.AssertNotError(t, err, "Could not create nonce service")

	n, err := ns1.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.Assert(t, !ns2.Valid(n), "Accepted a foreign nonce")
}

func TestRejectTooLate(t *testing.T) {
	ns, err := NewNonceService(metrics.NewNoopScope())
	test.AssertNotError(t, err, "Could not create nonce service")

	ns.latest = 2
	n, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	ns.latest = 1
	test.Assert(t, !ns.Valid(n), "Accepted a nonce with a too-high counter")
}

func TestRejectTooEarly(t *testing.T) {
	ns, err := NewNonceService(metrics.NewNoopScope())
	test.AssertNotError(t, err, "Could not create nonce service")
	ns.maxUsed = 2

	n0, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	n1, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	n2, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	n3, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")

	test.Assert(t, ns.Valid(n3), "Rejected a valid nonce")
	test.Assert(t, ns.Valid(n2), "Rejected a valid nonce")
	test.Assert(t, ns.Valid(n1), "Rejected a valid nonce")
	test.Assert(t, !ns.Valid(n0), "Accepted a nonce that we should have forgotten")
}

func BenchmarkGeneration(b *testing.B) {
	ns, err := NewNonceService(metrics.NewNoopScope())
	if err != nil {
		b.Fatal(err)
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := ns.Nonce()
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func BenchmarkValidation(b *testing.B) {
	b.Log("HELLO")
	ns, err := NewNonceService(metrics.NewNoopScope())
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 65536; i++ {
		_, err := ns.Nonce()
		if err != nil {
			b.Error(err)
		}
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			nonce, err := ns.Nonce()
			if err != nil {
				b.Error(err)
			}
			_ = ns.Valid(nonce)
		}
	})
}
