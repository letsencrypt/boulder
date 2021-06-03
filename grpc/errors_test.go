package grpc

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/jmhodges/clock"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/grpc/test_proto"
	testproto "github.com/letsencrypt/boulder/grpc/test_proto"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

type errorServer struct {
	test_proto.UnimplementedChillerServer
	err error
}

func (s *errorServer) Chill(_ context.Context, _ *testproto.Time) (*testproto.Time, error) {
	return nil, s.err
}

func TestErrorWrapping(t *testing.T) {
	serverMetrics := NewServerMetrics(metrics.NoopRegisterer)
	si := newServerInterceptor(serverMetrics, clock.NewFake())
	ci := clientInterceptor{time.Second, NewClientMetrics(metrics.NoopRegisterer), clock.NewFake()}
	srv := grpc.NewServer(grpc.UnaryInterceptor(si.intercept))
	es := &errorServer{}
	testproto.RegisterChillerServer(srv, es)
	lis, err := net.Listen("tcp", "127.0.0.1:")
	test.AssertNotError(t, err, "Failed to create listener")
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.Dial(
		lis.Addr().String(),
		grpc.WithInsecure(),
		grpc.WithUnaryInterceptor(ci.intercept),
	)
	test.AssertNotError(t, err, "Failed to dial grpc test server")
	client := testproto.NewChillerClient(conn)

	es.err = berrors.MalformedError("yup")
	_, err = client.Chill(context.Background(), &testproto.Time{})
	test.Assert(t, err != nil, fmt.Sprintf("nil error returned, expected: %s", err))
	test.AssertDeepEquals(t, err, es.err)

	test.AssertEquals(t, wrapError(context.Background(), nil), nil)
	test.AssertEquals(t, unwrapError(nil, nil), nil)
}

// TestSubErrorWrapping tests that a boulder error with suberrors can be
// correctly wrapped and unwrapped across the RPC layer.
func TestSubErrorWrapping(t *testing.T) {
	serverMetrics := NewServerMetrics(metrics.NoopRegisterer)
	si := newServerInterceptor(serverMetrics, clock.NewFake())
	ci := clientInterceptor{time.Second, NewClientMetrics(metrics.NoopRegisterer), clock.NewFake()}
	srv := grpc.NewServer(grpc.UnaryInterceptor(si.intercept))
	es := &errorServer{}
	testproto.RegisterChillerServer(srv, es)
	lis, err := net.Listen("tcp", "127.0.0.1:")
	test.AssertNotError(t, err, "Failed to create listener")
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.Dial(
		lis.Addr().String(),
		grpc.WithInsecure(),
		grpc.WithUnaryInterceptor(ci.intercept),
	)
	test.AssertNotError(t, err, "Failed to dial grpc test server")
	client := testproto.NewChillerClient(conn)

	subErrors := []berrors.SubBoulderError{
		{
			Identifier: identifier.DNSIdentifier("chillserver.com"),
			BoulderError: &berrors.BoulderError{
				Type:   berrors.RejectedIdentifier,
				Detail: "2 ill 2 chill",
			},
		},
	}

	es.err = (&berrors.BoulderError{
		Type:   berrors.Malformed,
		Detail: "malformed chill req",
	}).WithSubErrors(subErrors)

	_, err = client.Chill(context.Background(), &testproto.Time{})
	test.Assert(t, err != nil, fmt.Sprintf("nil error returned, expected: %s", err))
	test.AssertDeepEquals(t, err, es.err)
}
