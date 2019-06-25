package main

import (
	"context"
	"testing"
	"time"

	corepb "github.com/letsencrypt/boulder/core/proto"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/nonce"
	noncepb "github.com/letsencrypt/boulder/nonce/proto"
	"github.com/letsencrypt/boulder/test"
	"google.golang.org/grpc"
)

type workingRemote struct{ resp bool }

func (wr *workingRemote) Redeem(ctx context.Context, in *noncepb.NonceMessage, opts ...grpc.CallOption) (*noncepb.ValidMessage, error) {
	return &noncepb.ValidMessage{
		Valid: &wr.resp,
	}, nil
}

func (wr *workingRemote) Nonce(ctx context.Context, in *corepb.Empty, opts ...grpc.CallOption) (*noncepb.NonceMessage, error) {
	return nil, nil
}

type sleepingRemote struct{}

func (sr *sleepingRemote) Redeem(ctx context.Context, in *noncepb.NonceMessage, opts ...grpc.CallOption) (*noncepb.ValidMessage, error) {
	time.Sleep(time.Millisecond * 50)
	valid := true
	return &noncepb.ValidMessage{
		Valid: &valid,
	}, nil
}

func (sr *sleepingRemote) Nonce(ctx context.Context, in *corepb.Empty, opts ...grpc.CallOption) (*noncepb.NonceMessage, error) {
	return nil, nil
}

func TestRemoteRedeem(t *testing.T) {
	l := blog.NewMock()

	innerNs, err := nonce.NewNonceService(metrics.NewNoopScope(), 1)
	test.AssertNotError(t, err, "NewNonceService failed")
	ns := nonceServer{log: l, inner: innerNs}

	// Working remote returning valid nonce message
	ns.remoteServices = []noncepb.NonceServiceClient{
		&workingRemote{resp: false},
		&workingRemote{resp: true},
	}
	nonce := "asd"
	forwarded := false
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	resp, err := ns.Redeem(ctx, &noncepb.NonceMessage{Nonce: &nonce, Forwarded: &forwarded})
	cancel()
	test.AssertNotError(t, err, "Redeem failed")
	test.Assert(t, *resp.Valid, "Redeem returned the wrong response")

	// Working remote returning invalid nonce message
	ns.remoteServices = []noncepb.NonceServiceClient{
		&workingRemote{resp: false},
		&workingRemote{resp: false},
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	resp, err = ns.Redeem(ctx, &noncepb.NonceMessage{Nonce: &nonce, Forwarded: &forwarded})
	cancel()
	test.AssertNotError(t, err, "Redeem failed")
	test.Assert(t, !*resp.Valid, "Redeem returned the wrong response")

	// Sleeping remote returns valid nonce message, but after 50ms, Redeem should return false
	ns.remoteServices = []noncepb.NonceServiceClient{&sleepingRemote{}}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(time.Millisecond))
	resp, err = ns.Redeem(ctx, &noncepb.NonceMessage{Nonce: &nonce, Forwarded: &forwarded})
	cancel()
	test.AssertNotError(t, err, "Redeem failed")
	test.Assert(t, !*resp.Valid, "Redeem returned the wrong response")

	// Already forwarded message, Redeem should return false
	ns.remoteServices = []noncepb.NonceServiceClient{
		&workingRemote{resp: true},
		&workingRemote{resp: true},
	}
	forwarded = true
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	resp, err = ns.Redeem(ctx, &noncepb.NonceMessage{Nonce: &nonce, Forwarded: &forwarded})
	cancel()
	test.AssertNotError(t, err, "Redeem failed")
	test.Assert(t, !*resp.Valid, "Redeem returned the wrong response")
}
