package nonce

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/metrics"
	noncepb "github.com/letsencrypt/boulder/nonce/proto"
	"github.com/letsencrypt/boulder/test"
	"google.golang.org/grpc"
)

func TestValidNonce(t *testing.T) {
	ns, err := NewNonceService(metrics.NewNoopScope(), 0, nil)
	test.AssertNotError(t, err, "Could not create nonce service")
	n, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.Assert(t, ns.Valid(n), fmt.Sprintf("Did not recognize fresh nonce %s", n))
}

func TestAlreadyUsed(t *testing.T) {
	ns, err := NewNonceService(metrics.NewNoopScope(), 0, nil)
	test.AssertNotError(t, err, "Could not create nonce service")
	n, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.Assert(t, ns.Valid(n), "Did not recognize fresh nonce")
	test.Assert(t, !ns.Valid(n), "Recognized the same nonce twice")
}

func TestRejectMalformed(t *testing.T) {
	ns, err := NewNonceService(metrics.NewNoopScope(), 0, nil)
	test.AssertNotError(t, err, "Could not create nonce service")
	n, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.Assert(t, !ns.Valid("asdf"+n), "Accepted an invalid nonce")
}

func TestRejectShort(t *testing.T) {
	ns, err := NewNonceService(metrics.NewNoopScope(), 0, nil)
	test.AssertNotError(t, err, "Could not create nonce service")
	test.Assert(t, !ns.Valid("aGkK"), "Accepted an invalid nonce")
}

func TestRejectUnknown(t *testing.T) {
	ns1, err := NewNonceService(metrics.NewNoopScope(), 0, nil)
	test.AssertNotError(t, err, "Could not create nonce service")
	ns2, err := NewNonceService(metrics.NewNoopScope(), 0, nil)
	test.AssertNotError(t, err, "Could not create nonce service")

	n, err := ns1.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.Assert(t, !ns2.Valid(n), "Accepted a foreign nonce")
}

func TestRejectTooLate(t *testing.T) {
	ns, err := NewNonceService(metrics.NewNoopScope(), 0, nil)
	test.AssertNotError(t, err, "Could not create nonce service")

	ns.latest = 2
	n, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	ns.latest = 1
	test.Assert(t, !ns.Valid(n), "Accepted a nonce with a too-high counter")
}

func TestRejectTooEarly(t *testing.T) {
	ns, err := NewNonceService(metrics.NewNoopScope(), 0, nil)
	test.AssertNotError(t, err, "Could not create nonce service")

	n0, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")

	for i := 0; i < ns.maxUsed; i++ {
		n, err := ns.Nonce()
		test.AssertNotError(t, err, "Could not create nonce")
		if !ns.Valid(n) {
			t.Errorf("generated invalid nonce")
		}
	}

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

func BenchmarkNonces(b *testing.B) {
	ns, err := NewNonceService(metrics.NewNoopScope(), 0, nil)
	if err != nil {
		b.Fatal("creating nonce service", err)
	}

	for i := 0; i < ns.maxUsed; i++ {
		n, err := ns.Nonce()
		if err != nil {
			b.Fatal("noncing", err)
		}
		if !ns.Valid(n) {
			b.Fatal("generated invalid nonce")
		}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n, err := ns.Nonce()
			if err != nil {
				b.Fatal("noncing", err)
			}
			if !ns.Valid(n) {
				b.Fatal("generated invalid nonce")
			}
		}
	})
}

func TestNoncePrefixing(t *testing.T) {
	prefix := byte(5)
	ns, err := NewNonceService(metrics.NewNoopScope(), 0, &prefix)
	test.AssertNotError(t, err, "Could not create nonce service")

	n, err := ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	test.Assert(t, ns.Valid(n), "Valid nonce rejected")

	n, err = ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	nBytes, err := base64.RawURLEncoding.DecodeString(n)
	test.AssertNotError(t, err, "base64.RawURLEncoding.DecodeString failed")
	nBytes[0] = 1
	n = base64.RawURLEncoding.EncodeToString(nBytes)
	test.Assert(t, !ns.Valid(n), "Valid nonce with incorrect prefix accepted")

	n, err = ns.Nonce()
	test.AssertNotError(t, err, "Could not create nonce")
	nBytes, err = base64.RawURLEncoding.DecodeString(n)
	test.AssertNotError(t, err, "base64.RawURLEncoding.DecodeString failed")
	n = base64.RawURLEncoding.EncodeToString(nBytes[1:])
	test.Assert(t, !ns.Valid(n), "Valid nonce without prefix accepted")
}

type malleableNonceClient struct {
	redeem func(ctx context.Context, in *noncepb.NonceMessage, opts ...grpc.CallOption) (*noncepb.ValidMessage, error)
}

func (mnc *malleableNonceClient) Redeem(ctx context.Context, in *noncepb.NonceMessage, opts ...grpc.CallOption) (*noncepb.ValidMessage, error) {
	return mnc.redeem(ctx, in, opts...)
}

func (mnc *malleableNonceClient) Nonce(ctx context.Context, in *corepb.Empty, opts ...grpc.CallOption) (*noncepb.NonceMessage, error) {
	return nil, errors.New("unimplemented")
}

func TestRemoteRedeem(t *testing.T) {
	_, err := RemoteRedeem(context.Background(), nil, "q")
	test.AssertError(t, err, "RemoteRedeem accepted invalid nonce")
	valid, err := RemoteRedeem(context.Background(), nil, "")
	test.AssertNotError(t, err, "RemoteRedeem failed")
	test.Assert(t, !valid, "RemoteRedeem accepted a empty nonce")

	prefixMap := map[byte]noncepb.NonceServiceClient{
		2: &malleableNonceClient{
			redeem: func(ctx context.Context, in *noncepb.NonceMessage, opts ...grpc.CallOption) (*noncepb.ValidMessage, error) {
				return nil, errors.New("wrong one!")
			},
		},
		5: &malleableNonceClient{
			redeem: func(ctx context.Context, in *noncepb.NonceMessage, opts ...grpc.CallOption) (*noncepb.ValidMessage, error) {
				return &noncepb.ValidMessage{Valid: false}, nil
			},
		},
	}
	valid, err = RemoteRedeem(context.Background(), prefixMap, "CQEC")
	test.AssertNotError(t, err, "RemoteRedeem failed")
	test.Assert(t, !valid, "RemoteRedeem accepted nonce not in prefix map")
	_, err = RemoteRedeem(context.Background(), prefixMap, "AgEC")
	test.AssertError(t, err, "RemoteRedeem didn't return error when remote did")
	valid, err = RemoteRedeem(context.Background(), prefixMap, "BQEC")
	test.AssertNotError(t, err, "RemoteRedeem failed")
	test.Assert(t, !valid, "RemoteRedeem didn't honor remote result")
	prefixMap[5] = &malleableNonceClient{
		redeem: func(ctx context.Context, in *noncepb.NonceMessage, opts ...grpc.CallOption) (*noncepb.ValidMessage, error) {
			return &noncepb.ValidMessage{Valid: true}, nil
		},
	}
	valid, err = RemoteRedeem(context.Background(), prefixMap, "BQEC")
	test.AssertNotError(t, err, "RemoteRedeem failed")
	test.Assert(t, valid, "RemoteRedeem didn't honor remote result")
}
