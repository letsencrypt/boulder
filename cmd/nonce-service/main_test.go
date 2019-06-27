package main

import (
	"context"
	"errors"
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
		Valid: wr.resp,
	}, nil
}

func (wr *workingRemote) Nonce(ctx context.Context, in *corepb.Empty, opts ...grpc.CallOption) (*noncepb.NonceMessage, error) {
	return nil, nil
}

type sleepingRemote struct{}

func (sr *sleepingRemote) Redeem(ctx context.Context, in *noncepb.NonceMessage, opts ...grpc.CallOption) (*noncepb.ValidMessage, error) {
	time.Sleep(time.Millisecond * 50)
	return &noncepb.ValidMessage{
		Valid: true,
	}, nil
}

func (sr *sleepingRemote) Nonce(ctx context.Context, in *corepb.Empty, opts ...grpc.CallOption) (*noncepb.NonceMessage, error) {
	return nil, nil
}

type brokenRemote struct{}

func (br *brokenRemote) Redeem(ctx context.Context, in *noncepb.NonceMessage, opts ...grpc.CallOption) (*noncepb.ValidMessage, error) {
	return nil, errors.New("BROKE!")
}

func (br *brokenRemote) Nonce(ctx context.Context, in *corepb.Empty, opts ...grpc.CallOption) (*noncepb.NonceMessage, error) {
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
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	resp, err := ns.Redeem(ctx, &noncepb.NonceMessage{Nonce: nonce, Forwarded: false})
	cancel()
	test.AssertNotError(t, err, "Redeem failed")
	test.Assert(t, resp.Valid, "Redeem returned the wrong response")

	// Working remotes returning invalid nonce message
	ns.remoteServices = []noncepb.NonceServiceClient{
		&workingRemote{resp: false},
		&workingRemote{resp: false},
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	resp, err = ns.Redeem(ctx, &noncepb.NonceMessage{Nonce: nonce, Forwarded: false})
	cancel()
	test.AssertNotError(t, err, "Redeem failed")
	test.Assert(t, !resp.Valid, "Redeem returned the wrong response")

	// Sleeping remotes returns valid nonce message, but after 50ms, Redeem should return false
	ns.remoteServices = []noncepb.NonceServiceClient{
		&sleepingRemote{},
		&sleepingRemote{},
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(time.Millisecond))
	resp, err = ns.Redeem(ctx, &noncepb.NonceMessage{Nonce: nonce, Forwarded: false})
	cancel()
	test.AssertNotError(t, err, "Redeem failed")
	test.Assert(t, !resp.Valid, "Redeem returned the wrong response")

	// Already forwarded message, Redeem should return false
	ns.remoteServices = []noncepb.NonceServiceClient{
		&workingRemote{resp: true},
		&workingRemote{resp: true},
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	resp, err = ns.Redeem(ctx, &noncepb.NonceMessage{Nonce: nonce, Forwarded: true})
	cancel()
	test.AssertNotError(t, err, "Redeem failed")
	test.Assert(t, !resp.Valid, "Redeem returned the wrong response")

	// Broken remotes, Redeem should return false
	ns.remoteServices = []noncepb.NonceServiceClient{
		&brokenRemote{},
		&brokenRemote{},
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(time.Millisecond))
	resp, err = ns.Redeem(ctx, &noncepb.NonceMessage{Nonce: nonce, Forwarded: false})
	cancel()
	test.AssertNotError(t, err, "Redeem failed")
	test.Assert(t, !resp.Valid, "Redeem returned the wrong response")
}
