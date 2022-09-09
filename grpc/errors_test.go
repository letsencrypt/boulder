package grpc

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/jmhodges/clock"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/grpc/test_proto"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/metrics"
	"github.com/letsencrypt/boulder/test"
)

type errorServer struct {
	test_proto.UnimplementedChillerServer
	err error
}

func (s *errorServer) Chill(_ context.Context, _ *test_proto.Time) (*test_proto.Time, error) {
	return nil, s.err
}

func TestErrorWrapping(t *testing.T) {
	serverMetrics := NewServerMetrics(metrics.NoopRegisterer)
	si := newServerInterceptor(serverMetrics, clock.NewFake())
	ci := clientInterceptor{time.Second, NewClientMetrics(metrics.NoopRegisterer), clock.NewFake()}
	srv := grpc.NewServer(grpc.UnaryInterceptor(si.interceptUnary))
	es := &errorServer{}
	test_proto.RegisterChillerServer(srv, es)
	lis, err := net.Listen("tcp", "127.0.0.1:")
	test.AssertNotError(t, err, "Failed to create listener")
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.Dial(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(ci.interceptUnary),
	)
	test.AssertNotError(t, err, "Failed to dial grpc test server")
	client := test_proto.NewChillerClient(conn)

	es.err = berrors.MalformedError("yup")
	_, err = client.Chill(context.Background(), &test_proto.Time{})
	test.Assert(t, err != nil, fmt.Sprintf("nil error returned, expected: %s", err))
	test.AssertDeepEquals(t, err, es.err)

	test.AssertNil(t, wrapError(context.Background(), nil), "Wrapping nil should still be nil")
	test.AssertNil(t, unwrapError(nil, nil), "Unwrapping nil should still be nil")
}

// TestSubErrorWrapping tests that a boulder error with suberrors can be
// correctly wrapped and unwrapped across the RPC layer.
func TestSubErrorWrapping(t *testing.T) {
	serverMetrics := NewServerMetrics(metrics.NoopRegisterer)
	si := newServerInterceptor(serverMetrics, clock.NewFake())
	ci := clientInterceptor{time.Second, NewClientMetrics(metrics.NoopRegisterer), clock.NewFake()}
	srv := grpc.NewServer(grpc.UnaryInterceptor(si.interceptUnary))
	es := &errorServer{}
	test_proto.RegisterChillerServer(srv, es)
	lis, err := net.Listen("tcp", "127.0.0.1:")
	test.AssertNotError(t, err, "Failed to create listener")
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.Dial(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(ci.interceptUnary),
	)
	test.AssertNotError(t, err, "Failed to dial grpc test server")
	client := test_proto.NewChillerClient(conn)

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

	_, err = client.Chill(context.Background(), &test_proto.Time{})
	test.Assert(t, err != nil, fmt.Sprintf("nil error returned, expected: %s", err))
	test.AssertDeepEquals(t, err, es.err)
}
